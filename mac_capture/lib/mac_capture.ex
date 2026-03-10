defmodule MacCapture do
  @moduledoc """
  Captures NFC ISO15693 JSON lines from Arduino (nfc_tool) over serial and
  appends to a timestamped file and prints a short summary.

  Before capturing, prompts: "What are you scanning?" and stores the answer
  in each saved JSON line as the "item" field. After each tag is saved, it
  asks again for the next item so you can label each scan (e.g. "Vader minifigure", "Tie Fighter").

  Run with: mix run -e "NfcCapture.run()"
  Or: mix run -e "NfcCapture.run(port: \"/dev/cu.usbmodem14101\")"

  Requires Elixir 1.18+ (for built-in JSON module). Baud rate must match the
  Arduino sketch (115200).
  """

  @default_baud 115200
  @read_timeout_ms 500
  @nfc_prefix "NFC15693:"
  @sysinfo_prefix "SYSINFO:"
  @secstatus_prefix "SECSTATUS:"

  @doc """
  Lists available serial ports (from circuits_uart).
  """
  def list_ports do
    Circuits.UART.enumerate()
    |> Enum.each(fn {name, info} ->
      desc = info[:description] || ""
      IO.puts("  #{name}  #{desc}")
    end)
  end

  @doc """
  Runs the capture loop: open serial port, read line-by-line, parse NFC15693
  JSON lines, append to file and print summary. Exits on Ctrl+C.

  Options:
    - :port - serial port path (e.g. "/dev/cu.usbmodem14101"). If not set,
      tries to find a port with "usbmodem" in the name, or prompts.
    - :baud - baud rate (default 115200)
    - :output_dir - directory for dump files (default: ../data relative to cwd)
    - :debug - when true, also print Arduino debug lines starting with "[D]" or "[DEBUG]"
  """
  def run(opts \\ []) do
    port = (opts[:port] || find_usbmodem_port()) |> normalize_port()
    baud = opts[:baud] || @default_baud
    output_dir = opts[:output_dir] || Path.expand("../data", File.cwd!())
    File.mkdir_p!(output_dir)

    if is_nil(port) or port == "" do
      IO.puts("No serial port given. Available ports:")
      list_ports()
      IO.puts("\nUsage: NfcCapture.run(port: \"/dev/cu.usbmodemXXXX\")")
      :ok
    else
      date_str = Date.utc_today() |> Date.to_iso8601()
      output_path = Path.join(output_dir, "nfc_dump_#{date_str}.jsonl")
      IO.puts("NFC15693 capture — port: #{port}, baud: #{baud}")
      IO.puts("Output: #{output_path}")

      item = prompt_scan_item()
      IO.puts("Scanning: #{if item == "", do: "(no label)", else: item}")
      IO.puts("Press Ctrl+C to stop.\n")

      debug = opts[:debug] == true

      case Circuits.UART.start_link() do
        {:ok, pid} ->
          try do
            open_and_capture(pid, port, baud, output_path, item, debug)
          after
            Circuits.UART.close(pid)
            Circuits.UART.stop(pid)
          end
        {:error, _} = err ->
          err
      end
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
  defp normalize_port(""), do: nil
  defp normalize_port(name) when is_binary(name) do
    if String.starts_with?(name, "/") do
      name
    else
      "/dev/#{name}"
    end
  end

  defp prompt_scan_item do
    case IO.gets("What are you scanning? (e.g. Vader minifigure, Tie Fighter): ") do
      :eof -> ""
      line -> line |> to_string() |> String.trim()
    end
  end

  defp open_and_capture(pid, port, baud, output_path, item, debug) do
    opts = [speed: baud, active: false]

    case Circuits.UART.open(pid, port, opts) do
      :ok ->
        stream_capture(pid, output_path, "", item, debug)
      {:error, :einval} ->
        IO.puts("Failed to open #{port}: invalid argument (:einval).")
        IO.puts("  → Close the Arduino IDE Serial Monitor (or any other app using this port) and try again.")
        {:error, :einval}
      {:error, reason} ->
        IO.puts("Failed to open #{port}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp stream_capture(pid, output_path, buffer, item, debug) do
    case Circuits.UART.read(pid, @read_timeout_ms) do
      {:ok, <<>>} ->
        stream_capture(pid, output_path, buffer, item, debug)

      {:ok, data} ->
        new_buffer = buffer <> data
        {lines, rest} = split_lines(new_buffer)
        next_item =
          Enum.reduce(lines, item, fn line, current_item ->
            process_line(line, output_path, current_item, debug)
          end)

        stream_capture(pid, output_path, rest, next_item, debug)

      {:error, _reason} ->
        stream_capture(pid, output_path, buffer, item, debug)
    end
  end

  defp split_lines(binary) do
    parts = String.split(binary, ~r/\r\n|\r|\n/, include_captures: false)
    if parts == [] do
      {[], binary}
    else
      # If binary does not end with newline, last element is incomplete
      complete? = String.ends_with?(binary, "\n") or String.ends_with?(binary, "\r")
      if complete? do
        {Enum.reject(parts, &(&1 == "")), ""}
      else
        {complete, [rest]} = Enum.split(parts, -1)
        {Enum.reject(complete, &(&1 == "")), rest}
      end
    end
  end

  defp process_line(line, output_path, item, debug) do
    line = String.trim(line)
    cond do
      line == "" ->
        item
      String.starts_with?(line, "[D]") or String.starts_with?(line, "[DEBUG]") ->
        if debug, do: IO.puts("  < #{line}")
        item
      String.starts_with?(line, @sysinfo_prefix) ->
        json_str = String.trim_leading(line, @sysinfo_prefix)
        case JSON.decode(json_str) do
          {:ok, %{"error" => _} = info} ->
            IO.puts("[SYSINFO] error: #{inspect(info)}")
          {:ok, info} ->
            ic_ref = Map.get(info, "ic_ref", "?")
            num_blocks = Map.get(info, "num_blocks", "?")
            block_size = Map.get(info, "block_size", "?")
            uid = Map.get(info, "uid", "")
            mfr = case String.slice(uid, 12, 2) do
              "04" -> "NXP"
              "16" -> "EM Microelectronic"
              "02" -> "STMicroelectronics"
              "07" -> "Texas Instruments"
              code -> "mfr=0x#{code}"
            end
            total = if is_integer(num_blocks) and is_integer(block_size),
              do: " (#{num_blocks * block_size} bytes)", else: ""
            IO.puts("[SYSINFO] #{mfr} ic_ref=0x#{ic_ref} blocks=#{num_blocks}x#{block_size}#{total}")
          _ -> :ok
        end
        item
      String.starts_with?(line, @secstatus_prefix) ->
        json_str = String.trim_leading(line, @secstatus_prefix)
        case JSON.decode(json_str) do
          {:ok, info} ->
            locked = Map.get(info, "locked_count", "?")
            count = Map.get(info, "count", "?")
            IO.puts("[SECSTATUS] #{locked}/#{count} blocks locked")
          _ -> :ok
        end
        item
      true ->
        json_str = strip_prefix(line)
        case JSON.decode(json_str) do
          {:ok, map} when is_map(map) ->
            if Map.has_key?(map, "uid") and Map.has_key?(map, "blocks") do
              append_and_prompt_next(map, output_path, item)
            else
              item
            end
          _ ->
            item
        end
    end
  end

  defp strip_prefix(line) do
    if String.starts_with?(line, @nfc_prefix) do
      String.trim_leading(line, @nfc_prefix)
    else
      line
    end
  end

  defp append_and_prompt_next(map, output_path, item) do
    map = Map.put(map, "item", item)
    uid = Map.get(map, "uid", "")
    blocks = Map.get(map, "blocks", [])
    block_count = length(blocks)
    first_blocks = Enum.take(blocks, 3) |> Enum.join(", ")

    File.write!(output_path, JSON.encode!(map) <> "\n", [:append])
    label = if item == "", do: "", else: " item=#{item}"
    IO.puts("[NFC] uid=#{uid} blocks=#{block_count}#{label}  first=#{first_blocks}")
    next_item = prompt_scan_item()
    IO.puts("Next scan: #{if next_item == "", do: "(no label)", else: next_item}\n")
    next_item
  end
end
