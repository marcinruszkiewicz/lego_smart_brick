defmodule NfcCustomClone do
  @moduledoc """
  Experimental clone tool for custom `CLONE:<hex>` payloads.

  This keeps the normal `NfcClone` flow unchanged, but lets you:

  * Load a saved tag dump from `../data/*.jsonl`.
  * Optionally **truncate** it to a given number of blocks (e.g. 28 for 112-byte stickers).
  * **Rewrite block 0** (header) with a new payload length / capacity.
  * Or send an arbitrary **raw hex payload** to the Arduino.

  Run with:

      mix run -e "NfcCustomClone.run()"

  All paths reuse the same serial protocol and progress output as `NfcClone`.
  """

  @default_baud 115_200
  @read_timeout_ms 500

  @write_ok_prefix "WRITE_OK:"
  @write_fail_prefix "WRITE_FAIL:"
  @write_done_prefix "WRITE_DONE:"
  @clone_ready_prefix "CLONE_READY:"
  @clone_err_prefix "CLONE_ERR:"

  @doc """
  Entry point. Loads saved tags, lets you pick one, then offers experimental
  clone options for that tag.
  """
  def run(opts \\ []) do
    data_dir = opts[:data_dir] || Path.expand("../data", File.cwd!())
    tags = load_all_tags(data_dir)

    if tags == [] do
      IO.puts("No saved tags found in #{data_dir}")
      IO.puts("Run a capture first: mix run -e \"NfcCapture.run()\"")
      :ok
    else
      IO.puts("\n=== Experimental NFC Custom Clone ===\n")
      IO.puts("This tool may write invalid tags. Use only with blanks you are")
      IO.puts("comfortable experimenting on.\n")

      display_tag_menu(tags)

      case prompt_choice(length(tags)) do
        nil ->
          IO.puts("Cancelled.")
          :ok

        idx ->
          tag = Enum.at(tags, idx)
          experiment_menu(tag, opts)
      end
    end
  end

  # -- Tag loading / menu -----------------------------------------------------

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
    IO.puts("Saved NFC tags:\n")

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
    prompt = "Select tag (1-#{max}, or 'q' to cancel): "

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

  # -- Experiment menu --------------------------------------------------------

  defp experiment_menu(tag, opts) do
    item = Map.get(tag, "item", "(unknown)")
    uid = Map.get(tag, "uid", "?")
    blocks = Map.get(tag, "blocks", [])

    IO.puts("\n=== Experiments for: #{item} ===")
    IO.puts("UID: #{uid}")

    case blocks do
      [block0 | rest] ->
        total_blocks = length(blocks)
        {payload_len, capacity} = parse_block0_header(block0)

        IO.puts("Block 0: #{block0}")
        IO.puts("  -> decoded payload length: #{payload_len} bytes")
        IO.puts("  -> decoded capacity:       #{capacity} bytes")
        data_block_count = Enum.count(rest, &(&1 != "00000000" and &1 != "0001"))
        IO.puts("Total blocks in dump: #{total_blocks}")
        IO.puts("Data blocks (excluding trailing zeros/0001): #{data_block_count}")

      _ ->
        IO.puts("Tag has no blocks? Aborting.")
        :error
    end

    IO.puts("\nChoose an experiment:")
    IO.puts("  1. Reference clone (same as NfcClone)")
    IO.puts("  2. Truncate to sticker capacity and fix header (e.g. Lightsaber -> 28 blocks)")
    IO.puts("  3. Custom header-only tweak (edit block 0, optional truncate)")
    IO.puts("  4. Raw hex payload (paste full CLONE data)")
    IO.puts("  5. Flip one bit in a payload block (ciphertext corruption test)")
    IO.puts("  6. Format byte: change first byte of block 1 (normally 0x01)")
    IO.puts("  q. Cancel\n")

    case IO.gets("Experiment: ") do
      :eof ->
        IO.puts("Cancelled.")
        :ok

      input ->
        case String.trim(to_string(input)) do
          "1" -> experiment_reference_clone(blocks, opts)
          "2" -> experiment_truncate_and_fix_header(blocks, opts)
          "3" -> experiment_custom_header(blocks, opts)
          "4" -> experiment_raw_hex(opts)
          "5" -> experiment_flip_bit(blocks, opts)
          "6" -> experiment_format_byte(blocks, opts)
          _ ->
            IO.puts("Cancelled.")
            :ok
        end
    end
  end

  defp experiment_reference_clone(blocks, opts) do
    blocks = strip_trailing_filler(blocks)

    case prompt_blocks_to_write(blocks) do
      :cancel ->
        IO.puts("Cancelled.")
        :ok

      {:ok, to_write} ->
        IO.puts("\n[EXPERIMENT] Reference clone (#{length(to_write)} blocks)" <> padding_suffix(blocks, to_write))
        case confirm_write() do
          :cancel -> IO.puts("Cancelled."); :ok
          :confirm -> do_clone_blocks(to_write, opts)
        end
    end
  end

  defp experiment_truncate_and_fix_header(blocks, opts) do
    default_max = opts[:max_blocks] || 28

    max_blocks =
      case IO.gets("Max blocks to write (default #{default_max}): ") do
        :eof ->
          default_max

        input ->
          input = String.trim(to_string(input))

          cond do
            input == "" ->
              default_max

            true ->
              case Integer.parse(input) do
                {n, ""} when n >= 1 -> n
                _ ->
                  IO.puts("Invalid number, using default #{default_max}.")
                  default_max
              end
          end
      end

    if max_blocks < 1 do
      IO.puts("Max blocks must be at least 1.")
      :error
    else
      # Take first max_blocks from original (do not strip first), so we fill the sticker
      # and preserve the original payload length when it fits (e.g. X-Wing 107 bytes in 28 blocks).
      truncated = Enum.take(blocks, max_blocks)

      case truncated do
        [] ->
          IO.puts("Nothing to write after truncation.")
          :error

        [block0 | rest] ->
          {orig_payload_len, orig_capacity} = parse_block0_header(block0)
          payload_blocks = length(truncated) - 1
          max_payload_bytes = payload_blocks * 4
          # Use original payload length when it fits in what we're writing; else cap it.
          new_payload_len = min(orig_payload_len, max_payload_bytes) |> max(0)
          # Keep original capacity (0x010C = 268): the brick rejects tags if capacity is changed
          # to the physical sticker size (e.g. 112). Only payload length may need adjustment.
          new_block0 = build_block0_header(new_payload_len, orig_capacity)

          IO.puts("\n[EXPERIMENT] Truncate to sticker (keep original capacity)")
          IO.puts("Original block 0: #{block0}")
          IO.puts("  -> payload length: #{orig_payload_len} bytes")
          IO.puts("  -> capacity:       #{orig_capacity} bytes (kept — brick requires 0x010C)")
          IO.puts("New block 0:       #{new_block0}")
          IO.puts("  -> payload length: #{new_payload_len} bytes")
          IO.puts("  -> capacity:       #{orig_capacity} bytes (unchanged)")
          new_blocks = [new_block0 | rest]

          case prompt_blocks_to_write(new_blocks) do
            :cancel ->
              IO.puts("Cancelled.")
              :ok

            {:ok, to_write} ->
              IO.puts("Blocks to write:     #{length(to_write)}" <> padding_suffix(new_blocks, to_write))
              case confirm_write() do
                :cancel -> IO.puts("Cancelled."); :ok
                :confirm -> do_clone_blocks(to_write, opts)
              end
          end
      end
    end
  end

  defp experiment_custom_header(blocks, opts) do
    blocks = strip_trailing_filler(blocks)

    case blocks do
      [] ->
        IO.puts("No blocks to modify.")
        :error

      [block0 | rest] ->
        IO.puts("\nCurrent block 0: #{block0}")
        new_hex =
          case IO.gets("Enter new block 0 hex (8 chars, empty to cancel): ") do
            :eof -> ""
            input -> String.trim(to_string(input))
          end

        cond do
          new_hex == "" ->
            IO.puts("Cancelled.")
            :ok

          byte_size(new_hex) != 8 or not String.match?(new_hex, ~r/^[0-9A-Fa-f]{8}$/) ->
            IO.puts("Invalid hex (must be 8 hex characters).")
            :error

          true ->
            base = [String.upcase(new_hex) | rest]
            IO.puts("\n[EXPERIMENT] Custom header-only tweak")
            IO.puts("Old block 0: #{block0}")
            IO.puts("New block 0: #{String.upcase(new_hex)}")

            case prompt_blocks_to_write(base) do
              :cancel ->
                IO.puts("Cancelled.")
                :ok

              {:ok, to_write} ->
                IO.puts("Blocks to write: #{length(to_write)}" <> padding_suffix(base, to_write))
                case confirm_write() do
                  :cancel -> IO.puts("Cancelled."); :ok
                  :confirm -> do_clone_blocks(to_write, opts)
                end
            end
        end
    end
  end

  defp experiment_raw_hex(opts) do
    IO.puts("\nPaste full CLONE payload hex (concatenated 4-byte blocks).")
    IO.puts("Must be a multiple of 8 hex characters. Empty to cancel.\n")

    hex =
      case IO.gets("Hex: ") do
        :eof -> ""
        input -> String.trim(to_string(input))
      end

    cond do
      hex == "" ->
        IO.puts("Cancelled.")
        :ok

      rem(byte_size(hex), 8) != 0 or not String.match?(hex, ~r/^[0-9A-Fa-f]+$/) ->
        IO.puts("Invalid hex (must be hex and length multiple of 8).")
        :error

      true ->
        blocks = for <<chunk::binary-8 <- hex>>, do: String.upcase(chunk)
        IO.puts("\n[EXPERIMENT] Raw hex payload")

        case prompt_blocks_to_write(blocks) do
          :cancel ->
            IO.puts("Cancelled.")
            :ok

          {:ok, to_write} ->
            IO.puts("Blocks to write: #{length(to_write)}" <> padding_suffix(blocks, to_write))
            case confirm_write() do
              :cancel -> IO.puts("Cancelled."); :ok
              :confirm -> do_clone_blocks(to_write, opts)
            end
        end
    end
  end

  defp experiment_flip_bit(blocks, opts) do
    blocks = strip_trailing_filler(blocks)
    n = length(blocks)

    if n < 2 do
      IO.puts("Need at least 2 blocks (header + payload).")
      :error
    else
      default_idx = 5
      block_idx =
        case IO.gets("Block index to corrupt (0=header, 1=first payload; default #{default_idx}): ") do
          :eof -> default_idx
          input ->
            s = String.trim(to_string(input))
            if s == "" do
              default_idx
            else
              case Integer.parse(s) do
                {i, ""} when i >= 0 and i < n -> i
                _ ->
                  IO.puts("Invalid index (0-#{n - 1}), using #{default_idx}.")
                  default_idx
              end
            end
        end

      default_byte = 0
      byte_in_block =
        case IO.gets("Byte within block (0-3; default #{default_byte}): ") do
          :eof -> default_byte
          input ->
            s = String.trim(to_string(input))
            if s == "" do
              default_byte
            else
              case Integer.parse(s) do
                {b, ""} when b >= 0 and b <= 3 -> b
                _ ->
                  IO.puts("Invalid byte (0-3), using #{default_byte}.")
                  default_byte
              end
            end
        end

      default_bit = 0
      bit_idx =
        case IO.gets("Bit to flip (0-7; default #{default_bit}): ") do
          :eof -> default_bit
          input ->
            s = String.trim(to_string(input))
            if s == "" do
              default_bit
            else
              case Integer.parse(s) do
                {b, ""} when b >= 0 and b <= 7 -> b
                _ ->
                  IO.puts("Invalid bit (0-7), using #{default_bit}.")
                  default_bit
              end
            end
        end

      block_hex = Enum.at(blocks, block_idx)
      case flip_bit_in_block(block_hex, byte_in_block, bit_idx) do
        {:ok, new_block_hex} ->
          modified = List.replace_at(blocks, block_idx, new_block_hex)
          IO.puts("\n[EXPERIMENT] Flip one bit in payload (ciphertext corruption)")
          IO.puts("Block #{block_idx}, byte #{byte_in_block}, bit #{bit_idx}: #{block_hex} -> #{new_block_hex}")

          case prompt_blocks_to_write(modified) do
            :cancel ->
              IO.puts("Cancelled.")
              :ok

            {:ok, to_write} ->
              IO.puts("Blocks to write: #{length(to_write)}" <> padding_suffix(modified, to_write))
              case confirm_write() do
                :cancel -> IO.puts("Cancelled."); :ok
                :confirm -> do_clone_blocks(to_write, opts)
              end
          end

        :error ->
          IO.puts("Invalid block hex (must be 8 hex chars).")
          :error
      end
    end
  end

  defp experiment_format_byte(blocks, opts) do
    blocks = strip_trailing_filler(blocks)

    if length(blocks) < 2 do
      IO.puts("Need at least 2 blocks (header + block 1).")
      :error
    else
      block1 = Enum.at(blocks, 1)
      current_byte_hex = String.slice(block1, 0, 2)
      current_byte = String.to_integer(current_byte_hex, 16)
      IO.puts("\nBlock 1: #{block1}  (first byte = 0x#{String.upcase(current_byte_hex)} = #{current_byte})")
      IO.puts("Normal value is 0x01. Try 0x00, 0x02, 0xFF to see how the brick reacts.\n")

      new_byte =
        case IO.gets("New format byte (hex 00-FF or decimal 0-255; default 01): ") do
          :eof -> 0x01
          input ->
            s = String.trim(to_string(input))
            cond do
              s == "" -> 0x01
              # One or two hex digits (e.g. 0, 01, 00, FF)
              String.match?(s, ~r/^[0-9A-Fa-f]{1,2}$/) ->
                String.to_integer(String.pad_leading(s, 2, "0"), 16)
              true ->
                case Integer.parse(s) do
                  {n, ""} when n in 0..255 -> n
                  _ ->
                    IO.puts("Invalid; using 0x01.")
                    0x01
                end
            end
        end

      new_byte_hex = new_byte |> Integer.to_string(16) |> String.pad_leading(2, "0") |> String.upcase()
      rest_of_block1 = String.slice(block1, 2, 6)
      new_block1 = new_byte_hex <> rest_of_block1
      modified = List.replace_at(blocks, 1, new_block1)

      IO.puts("\n[EXPERIMENT] Format byte: block 1 first byte 0x#{current_byte_hex} -> 0x#{new_byte_hex}")
      IO.puts("Block 1: #{block1} -> #{new_block1}")

      case prompt_blocks_to_write(modified) do
        :cancel ->
          IO.puts("Cancelled.")
          :ok

        {:ok, to_write} ->
          IO.puts("Blocks to write: #{length(to_write)}" <> padding_suffix(modified, to_write))
          case confirm_write() do
            :cancel -> IO.puts("Cancelled."); :ok
            :confirm -> do_clone_blocks(to_write, opts)
          end
      end
    end
  end

  # Flip one bit in a 4-byte block (8 hex chars). byte_index 0..3, bit_index 0..7.
  defp flip_bit_in_block(block_hex, byte_index, bit_index)
       when byte_size(block_hex) == 8 and byte_index in 0..3 and bit_index in 0..7 do
    try do
      bin = Base.decode16!(String.upcase(block_hex), case: :mixed)
      <<b0, b1, b2, b3>> = bin
      bytes = [b0, b1, b2, b3]
      old_byte = Enum.at(bytes, byte_index)
      new_byte = :erlang.bxor(old_byte, :erlang.bsl(1, bit_index))
      new_bytes = List.replace_at(bytes, byte_index, new_byte)
      new_bin = :erlang.list_to_binary(new_bytes)
      new_hex = Base.encode16(new_bin, case: :upper)
      {:ok, new_hex}
    rescue
      _ -> :error
    end
  end

  defp flip_bit_in_block(_, _, _), do: :error

  # -- Block helpers ----------------------------------------------------------

  defp prompt_blocks_to_write(blocks) do
    default = length(blocks)
    case IO.gets("How many blocks to write (default #{default}, pad with zeros): ") do
      :eof ->
        :cancel

      input ->
        s = String.trim(to_string(input))
        total =
          if s == "" do
            default
          else
            case Integer.parse(s) do
              {n, ""} when n >= 1 -> n
              _ ->
                IO.puts("Invalid number, using #{default}.")
                default
            end
          end
        {:ok, maybe_pad_or_truncate(blocks, total)}
    end
  end

  defp maybe_pad_or_truncate(blocks, total) do
    n = length(blocks)
    cond do
      total <= 0 -> Enum.take(blocks, 1)
      total <= n -> Enum.take(blocks, total)
      true -> blocks ++ List.duplicate("00000000", total - n)
    end
  end

  defp padding_suffix(original, to_write) do
    pad = length(to_write) - length(original)
    if pad > 0, do: " (+#{pad} zero blocks to fill sticker)", else: ""
  end

  defp confirm_write do
    case IO.gets("Proceed with write? [y/N]: ") do
      :eof -> :cancel
      reply ->
        if String.downcase(String.trim(to_string(reply))) in ["y", "yes"], do: :confirm, else: :cancel
    end
  end

  defp strip_trailing_filler(blocks) do
    blocks
    |> Enum.reverse()
    |> Enum.drop_while(&(&1 == "0001"))
    |> Enum.drop_while(&(&1 == "00000000"))
    |> Enum.reverse()
  end

  # block0 from dump is 8 hex chars, e.g. "007E010C" -> payload_len (bytes 0-1 BE), capacity (bytes 2-3 BE)
  defp parse_block0_header(block0) when is_binary(block0) and byte_size(block0) == 8 do
    <<a::binary-4, b::binary-4>> = block0
    with {:ok, payload_len} <- hex16_to_int(a),
         {:ok, capacity} <- hex16_to_int(b) do
      {payload_len, capacity}
    else
      _ -> {0, 0}
    end
  end

  defp parse_block0_header(_), do: {0, 0}

  defp build_block0_header(payload_len, capacity_bytes) do
    <<pl_hi, pl_lo>> = <<payload_len::16>>
    <<cap_hi, cap_lo>> = <<capacity_bytes::16>>

    [pl_hi, pl_lo, cap_hi, cap_lo]
    |> Enum.map(&Integer.to_string(&1, 16) |> String.upcase() |> String.pad_leading(2, "0"))
    |> Enum.join()
  end

  defp hex16_to_int(<<h::binary-4>>) do
    case Integer.parse(h, 16) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end

  # -- Serial / CLONE plumbing (mirrors NfcClone) -----------------------------

  defp do_clone_blocks(blocks, opts) do
    hex = Enum.join(blocks)
    total_blocks = length(blocks)

    port = (opts[:port] || find_usbmodem_port()) |> normalize_port()
    baud = opts[:baud] || @default_baud
    debug = opts[:debug] == true

    if is_nil(port) do
      IO.puts("No serial port found. Available ports:")
      MacCapture.list_ports()
      :error
    else
      IO.puts("Using port: #{port}")

      case Circuits.UART.start_link() do
        {:ok, pid} ->
          try do
            do_clone(pid, port, baud, hex, total_blocks, debug)
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

  defp do_clone(pid, port, baud, hex, total_blocks, debug) do
    case Circuits.UART.open(pid, port, speed: baud, active: false) do
      :ok ->
        drain_startup(pid)

        if debug, do: IO.puts("(Debug: showing Arduino [DEBUG] lines)")

        IO.puts("Sending CLONE command (#{total_blocks} blocks)...")
        IO.puts("(If Arduino is busy reading a tag, remove it so CLONE can be accepted.)")
        Circuits.UART.write(pid, "CLONE:#{hex}\n")

        IO.puts("Waiting for Arduino to acknowledge...")
        case wait_for_ack(pid, 0, "", debug) do
          :ok ->
            IO.puts("Present a blank tag to the reader.\n")
            wait_for_write_results(pid, total_blocks, 0, 0, debug)

          other ->
            other
        end

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

  defp wait_for_ack(_pid, attempts, _buffer, _debug)
       when attempts > 60 do
    IO.puts("Timed out waiting for CLONE_READY from Arduino.")
    :timeout
  end

  defp wait_for_ack(pid, attempts, buffer, debug) do
    case Circuits.UART.read(pid, @read_timeout_ms) do
      {:ok, <<>>} ->
        wait_for_ack(pid, attempts + 1, buffer, debug)

      {:ok, data} ->
        buffer = buffer <> data

        parts = String.split(buffer, ~r/\r\n|\r|\n/, trim: false)

        {complete_lines, rest} =
          if String.ends_with?(buffer, "\n") or String.ends_with?(buffer, "\r") do
            {Enum.reject(parts, &(&1 == "")), ""}
          else
            complete = Enum.drop(parts, -1)
            rest = List.last(parts) || ""
            {complete, rest}
          end

        ack_line =
          Enum.find(complete_lines, fn line ->
            String.starts_with?(line, @clone_ready_prefix) or
              String.starts_with?(line, @clone_err_prefix)
          end)

        ack_line =
          cond do
            ack_line -> ack_line
            String.contains?(buffer, "CLONE_READY:") -> "CLONE_READY:ok"
            String.contains?(buffer, "CLONE_ERR:") -> "CLONE_ERR:ok"
            true -> nil
          end

        Enum.each(complete_lines, fn line ->
          line = String.trim(line)
          show = line != "" and (debug or (!String.starts_with?(line, "[DEBUG]") and !String.starts_with?(line, "[D]")))
          if show, do: IO.puts("  < #{line}")
        end)

        case ack_line do
          nil ->
            wait_for_ack(pid, attempts + 1, rest, debug)

          line when is_binary(line) ->
            if String.starts_with?(line, @clone_err_prefix) do
              IO.puts("\nArduino rejected the clone data.")
              :error
            else
              :ok
            end
        end

      {:error, _} ->
        wait_for_ack(pid, attempts + 1, buffer, debug)
    end
  end

  defp wait_for_write_results(pid, total, ok_count, fail_count, debug) do
    case Circuits.UART.read(pid, @read_timeout_ms) do
      {:ok, <<>>} ->
        wait_for_write_results(pid, total, ok_count, fail_count, debug)

      {:ok, data} ->
        lines = String.split(data, ~r/\r\n|\r|\n/, trim: true)

        {new_ok, new_fail, done?} =
          Enum.reduce(lines, {ok_count, fail_count, false}, fn line, {ok, fail, done} ->
            line = String.trim(line)

            if debug and (String.starts_with?(line, "[DEBUG]") or String.starts_with?(line, "[D]")) do
              IO.puts("  < #{line}")
            end

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
          wait_for_write_results(pid, total, new_ok, new_fail, debug)
        end

      {:error, _} ->
        wait_for_write_results(pid, total, ok_count, fail_count, debug)
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

