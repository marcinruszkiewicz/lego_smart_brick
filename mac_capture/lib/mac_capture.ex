defmodule MacCapture do
  @moduledoc """
  Captures NFC ISO15693 JSON lines from Arduino (nfc_tool) over serial and
  appends to a timestamped file and prints a short summary.

  Before capturing, prompts for "What are you scanning?" (item label) and
  "Category (identity/item/unknown)". Both are stored in each JSON line as
  "item" and "category". After each tag is saved, it asks again for the next
  item and category.

  Run with: mix run -e "NfcCapture.run()"
  Or: mix run -e "NfcCapture.run(port: \"/dev/cu.usbmodem14101\")"

  Requires Elixir 1.18+ (for built-in JSON module). Baud rate must match the
  Arduino sketch (115200).
  """

  @default_baud 115200
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
      category = prompt_scan_category()
      label = if item == "", do: "(no label)", else: item
      IO.puts("Scanning: #{label}, category=#{category}")
      IO.puts("Press Ctrl+C to stop.")
      IO.puts("Place the tag on the reader now (or remove and re-place if it's already there).\n")

      debug = opts[:debug] == true

      case Circuits.UART.start_link() do
        {:ok, pid} ->
          try do
            open_and_capture(pid, port, baud, output_path, item, category, debug)
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
    case IO.gets("What are you scanning? (e.g. Falcon, Vader, X-Wing): ") do
      :eof -> ""
      line -> line |> to_string() |> String.trim()
    end
  end

  defp prompt_scan_category do
    case IO.gets("Category (identity/item/unknown) [unknown]: ") do
      :eof -> "unknown"
      line ->
        s = line |> to_string() |> String.trim() |> String.downcase()
        if s == "", do: "unknown",
        else: if(s in ["identity", "item", "unknown"], do: s, else: "unknown")
    end
  end

  defp open_and_capture(pid, port, baud, output_path, item, category, debug) do
    # active: true so this process receives UART data as messages while we wait for prompt
    opts = [speed: baud, active: true]

    case Circuits.UART.open(pid, port, opts) do
      :ok ->
        receive_loop(output_path, {item, category, [], ""}, debug)
      {:error, :einval} ->
        IO.puts("Failed to open #{port}: invalid argument (:einval).")
        IO.puts("  → Close the Arduino IDE Serial Monitor (or any other app using this port) and try again.")
        {:error, :einval}
      {:error, reason} ->
        IO.puts("Failed to open #{port}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp receive_loop(output_path, state, debug) do
    new_state =
      receive do
        {:circuits_uart, _port_id, data} when is_binary(data) ->
          handle_uart_data(data, output_path, state, debug)
        {:circuits_uart, _port_id, {:error, _reason}} ->
          state
        {:next_item, item, category} ->
          handle_next_item(item, category, output_path, state, debug)
      end
    receive_loop(output_path, new_state, debug)
  end

  defp handle_uart_data(data, output_path, {current_item, current_category, queue, buffer}, debug) do
    new_buffer = buffer <> data
    {lines, rest} = split_lines(new_buffer)
    if debug and length(lines) > 0 do
      nfc_count = Enum.count(lines, &String.starts_with?(&1, @nfc_prefix))
      if nfc_count > 0, do: IO.puts("  < [capture] #{length(lines)} line(s), #{nfc_count} NFC15693")
    end
    state = {current_item, current_category, queue, rest}
    Enum.reduce(lines, state, fn line, acc ->
      {item, cat, q, buf} = acc
      {new_item, new_cat, new_queue, _} = handle_uart_line(line, output_path, {item, cat, q, buf}, debug)
      {new_item, new_cat, new_queue, buf}
    end)
  end

  defp handle_uart_line(line, output_path, {current_item, current_category, queue, buffer}, debug) do
    case process_line(line, output_path, debug) do
      :no_tag ->
        {current_item, current_category, queue, buffer}
      {:tag, map} ->
        if current_item != :pending do
          append_and_save(map, output_path, current_item, current_category)
          request_next_item()
          {:pending, :pending, queue, buffer}
        else
          {:pending, :pending, queue ++ [map], buffer}
        end
    end
  end

  defp handle_next_item(item, category, output_path, {:pending, _cat, queue, buffer}, _debug) do
    case queue do
      [] ->
        label = if item == "", do: "(no label)", else: item
        IO.puts("Next scan: #{label}, category=#{category}\n")
        {item, category, [], buffer}
      [tag | rest] ->
        append_and_save(tag, output_path, item, category)
        label = if item == "", do: "(no label)", else: item
        IO.puts("Next scan: #{label}, category=#{category}\n")
        request_next_item()
        {:pending, :pending, rest, buffer}
    end
  end

  defp request_next_item do
    main = self()
    Task.start(fn ->
      item = prompt_scan_item()
      category = prompt_scan_category()
      send(main, {:next_item, item, category})
    end)
  end

  defp append_and_save(map, output_path, item, category) do
    map = Map.put(map, "item", item) |> Map.put("category", category)
    uid = Map.get(map, "uid", "")
    blocks = Map.get(map, "blocks", [])
    block_count = length(blocks)
    first_blocks = Enum.take(blocks, 3) |> Enum.join(", ")

    File.write!(output_path, JSON.encode!(map) <> "\n", [:append])
    label = if item == "", do: "", else: " item=#{item}"
    IO.puts("[NFC] uid=#{uid} blocks=#{block_count}#{label} category=#{category}  first=#{first_blocks}")
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

  defp process_line(line, _output_path, debug) do
    line = String.trim(line)
    cond do
      line == "" ->
        :no_tag
      String.starts_with?(line, "[D]") or String.starts_with?(line, "[DEBUG]") ->
        if debug, do: IO.puts("  < #{line}")
        :no_tag
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
        :no_tag
      String.starts_with?(line, @secstatus_prefix) ->
        json_str = String.trim_leading(line, @secstatus_prefix)
        case JSON.decode(json_str) do
          {:ok, info} ->
            locked = Map.get(info, "locked_count", "?")
            count = Map.get(info, "count", "?")
            IO.puts("[SECSTATUS] #{locked}/#{count} blocks locked")
          _ -> :ok
        end
        :no_tag
      true ->
        json_str = strip_prefix(line)
        case JSON.decode(json_str) do
          {:ok, map} when is_map(map) ->
            if Map.has_key?(map, "uid") and Map.has_key?(map, "blocks") do
              {:tag, map}
            else
              :no_tag
            end
          _ ->
            if debug and String.starts_with?(line, @nfc_prefix) do
              IO.puts("  < [capture] NFC15693 line received but parse failed (incomplete chunk?)")
            end
            :no_tag
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

end
