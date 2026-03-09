defmodule NfcClone do
  @moduledoc """
  Clone mode: load saved NFC tag dumps, pick one, write it to a blank tag.

  Run with: mix run -e "NfcClone.run()"
  Or: mix run -e "NfcClone.run(port: \"/dev/cu.usbmodem14101\")"
  """

  @default_baud 115200
  @read_timeout_ms 500

  @write_ok_prefix "WRITE_OK:"
  @write_fail_prefix "WRITE_FAIL:"
  @write_done_prefix "WRITE_DONE:"
  @clone_ready_prefix "CLONE_READY:"
  @clone_err_prefix "CLONE_ERR:"

  def run(opts \\ []) do
    data_dir = opts[:data_dir] || Path.expand("../data", File.cwd!())
    tags = load_all_tags(data_dir)

    if tags == [] do
      IO.puts("No saved tags found in #{data_dir}")
      IO.puts("Run a capture first: mix run -e \"NfcCapture.run()\"")
      :ok
    else
      display_tag_menu(tags)

      case prompt_choice(length(tags)) do
        nil ->
          IO.puts("Cancelled.")
        idx ->
          tag = Enum.at(tags, idx)
          clone_tag(tag, opts)
      end
    end
  end

  defp load_all_tags(data_dir) do
    Path.wildcard(Path.join(data_dir, "*.jsonl"))
    |> Enum.flat_map(&load_jsonl_file/1)
    |> dedup_by_content()
    |> Enum.sort_by(& &1["item"])
  end

  defp load_jsonl_file(path) do
    File.read!(path)
    |> String.split("\n", trim: true)
    |> Enum.flat_map(fn line ->
      case JSON.decode(line) do
        {:ok, %{"blocks" => blocks} = map} when is_list(blocks) and blocks != [] ->
          source = Path.basename(path)
          [Map.put(map, "_source", source)]
        _ ->
          []
      end
    end)
  end

  defp dedup_by_content(tags) do
    tags
    |> Enum.uniq_by(fn tag ->
      blocks = Map.get(tag, "blocks", [])
      payload_blocks = Enum.reject(blocks, &(&1 == "00000000" or &1 == "0001"))
      Enum.join(payload_blocks)
    end)
  end

  defp display_tag_menu(tags) do
    IO.puts("\n=== Saved NFC Tags ===\n")

    tags
    |> Enum.with_index(1)
    |> Enum.each(fn {tag, idx} ->
      item = Map.get(tag, "item", "(unknown)")
      uid = Map.get(tag, "uid", "?")
      blocks = Map.get(tag, "blocks", [])
      payload_count = Enum.count(blocks, &(&1 != "00000000" and &1 != "0001"))
      source = Map.get(tag, "_source", "")

      IO.puts("  #{pad_num(idx, length(tags))}. #{item}")
      IO.puts("     UID: #{uid}  |  #{payload_count} data blocks  |  from: #{source}")
    end)

    IO.puts("")
  end

  defp pad_num(n, max) do
    width = max |> Integer.to_string() |> String.length()
    n |> Integer.to_string() |> String.pad_leading(width)
  end

  defp prompt_choice(max) do
    prompt = "Select tag to clone (1-#{max}, or 'q' to cancel): "

    case IO.gets(prompt) do
      :eof ->
        nil

      input ->
        input = input |> to_string() |> String.trim()

        cond do
          input in ["q", "Q", "quit", "cancel", ""] ->
            nil

          true ->
            case Integer.parse(input) do
              {n, ""} when n >= 1 and n <= max -> n - 1
              _ ->
                IO.puts("Invalid choice.")
                prompt_choice(max)
            end
        end
    end
  end

  defp clone_tag(tag, opts) do
    item = Map.get(tag, "item", "(unknown)")
    blocks = Map.get(tag, "blocks", [])

    blocks = strip_trailing_filler(blocks)
    hex = Enum.join(blocks)

    IO.puts("\nCloning: #{item}")
    IO.puts("Blocks to write: #{length(blocks)} (#{byte_size(hex) |> div(2)} bytes)")
    IO.puts("")

    port = (opts[:port] || find_usbmodem_port()) |> normalize_port()
    baud = opts[:baud] || @default_baud

    if is_nil(port) do
      IO.puts("No serial port found. Available ports:")
      MacCapture.list_ports()
      :error
    else
      IO.puts("Using port: #{port}")

      case Circuits.UART.start_link() do
        {:ok, pid} ->
          try do
            do_clone(pid, port, baud, hex, length(blocks))
          after
            Circuits.UART.close(pid)
            Circuits.UART.stop(pid)
          end

        {:error, reason} ->
          IO.puts("Failed to start UART: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  defp strip_trailing_filler(blocks) do
    blocks
    |> Enum.reverse()
    |> Enum.drop_while(&(&1 == "0001"))
    |> Enum.drop_while(&(&1 == "00000000"))
    |> Enum.reverse()
  end

  defp do_clone(pid, port, baud, hex, total_blocks) do
    case Circuits.UART.open(pid, port, speed: baud, active: false) do
      :ok ->
        drain_startup(pid)

        IO.puts("Sending CLONE command (#{total_blocks} blocks)...")
        Circuits.UART.write(pid, "CLONE:#{hex}\n")

        IO.puts("Waiting for Arduino to acknowledge...")
        wait_for_ack(pid, 0)

        IO.puts("Present a blank tag to the reader.\n")
        wait_for_write_results(pid, total_blocks, 0, 0)

      {:error, :einval} ->
        IO.puts("Failed to open #{port}: port busy.")
        IO.puts("  -> Close Arduino IDE Serial Monitor and try again.")
        {:error, :einval}

      {:error, reason} ->
        IO.puts("Failed to open #{port}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp drain_startup(pid) do
    case Circuits.UART.read(pid, 1000) do
      {:ok, data} when byte_size(data) > 0 -> drain_startup(pid)
      _ -> :ok
    end
  end

  defp wait_for_ack(_pid, attempts) when attempts > 60 do
    IO.puts("Timed out waiting for CLONE_READY from Arduino.")
    :timeout
  end

  defp wait_for_ack(pid, attempts) do
    case Circuits.UART.read(pid, @read_timeout_ms) do
      {:ok, <<>>} ->
        wait_for_ack(pid, attempts + 1)

      {:ok, data} ->
        lines = String.split(data, ~r/\r\n|\r|\n/, trim: true)

        ack =
          Enum.find(lines, fn line ->
            String.starts_with?(line, @clone_ready_prefix) or
              String.starts_with?(line, @clone_err_prefix)
          end)

        Enum.each(lines, fn line ->
          line = String.trim(line)
          if line != "" and !String.starts_with?(line, "[DEBUG]"), do: IO.puts("  < #{line}")
        end)

        case ack do
          nil -> wait_for_ack(pid, attempts + 1)
          line when is_binary(line) ->
            if String.starts_with?(line, @clone_err_prefix) do
              IO.puts("\nArduino rejected the clone data.")
              :error
            else
              :ok
            end
        end

      {:error, _} ->
        wait_for_ack(pid, attempts + 1)
    end
  end

  defp wait_for_write_results(pid, total, ok_count, fail_count) do
    case Circuits.UART.read(pid, @read_timeout_ms) do
      {:ok, <<>>} ->
        wait_for_write_results(pid, total, ok_count, fail_count)

      {:ok, data} ->
        lines = String.split(data, ~r/\r\n|\r|\n/, trim: true)

        {new_ok, new_fail, done?} =
          Enum.reduce(lines, {ok_count, fail_count, false}, fn line, {ok, fail, done} ->
            line = String.trim(line)

            cond do
              String.starts_with?(line, @write_ok_prefix) ->
                progress_bar(ok + fail + 1, total)
                {ok + 1, fail, done}

              String.starts_with?(line, @write_fail_prefix) ->
                detail = String.trim_leading(line, @write_fail_prefix)
                IO.puts("\n  FAIL block #{detail}")
                {ok, fail + 1, done}

              String.starts_with?(line, @write_done_prefix) ->
                {ok, fail, true}

              String.starts_with?(line, "[CLONE]") ->
                IO.puts("  #{line}")
                {ok, fail, done}

              true ->
                {ok, fail, done}
            end
          end)

        if done? do
          IO.puts("")
          finish_clone(new_ok, new_fail, total)
        else
          wait_for_write_results(pid, total, new_ok, new_fail)
        end

      {:error, _} ->
        wait_for_write_results(pid, total, ok_count, fail_count)
    end
  end

  defp progress_bar(current, total) do
    pct = round(current / total * 100)
    bar_width = 40
    filled = round(current / total * bar_width)
    bar = String.duplicate("█", filled) <> String.duplicate("░", bar_width - filled)
    IO.write("\r  Writing: [#{bar}] #{current}/#{total} (#{pct}%)")
  end

  defp finish_clone(ok, fail, total) do
    IO.puts("\n=== Clone Result ===")
    IO.puts("  Total blocks: #{total}")
    IO.puts("  Written OK:   #{ok}")

    if fail > 0 do
      IO.puts("  FAILED:       #{fail}")
      IO.puts("\n  Some blocks failed to write. The tag may be partially written")
      IO.puts("  or write-locked. Try with a fresh blank tag.")
    else
      IO.puts("\n  Clone successful! All #{ok} blocks written and verified.")
    end
  end

  defp find_usbmodem_port do
    Circuits.UART.enumerate()
    |> Map.keys()
    |> Enum.find(fn name ->
      name =~ ~r/usbmodem|tty\.usbmodem/i
    end)
  end

  defp normalize_port(nil), do: nil
  defp normalize_port(name) when is_binary(name) do
    if String.starts_with?(name, "/"), do: name, else: "/dev/#{name}"
  end
end
