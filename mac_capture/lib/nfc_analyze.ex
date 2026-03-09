defmodule NfcAnalyze do
  @moduledoc """
  Analyze LEGO smart brick NFC dumps (JSONL from mac_capture).

  Uses the header (block 0 bytes 0–1) as payload length in bytes; there is no
  terminator — the last data block is end-of-data plus zero padding. Payload
  is trimmed to that length when present.

  Run with:
    mix run -e "NfcAnalyze.run()"
    mix run -e "NfcAnalyze.run(\"path/to/nfc_dump_2026-03-07.jsonl\")"
  """

  def run(jsonl_path \\ nil) do
    path = jsonl_path || default_dump_path()
    tags = load_tags(path)
    IO.puts("Loaded #{length(tags)} tag(s) from #{path}\n")
    if length(tags) >= 2, do: compare_two(List.first(tags), List.last(tags))
    Enum.each(tags, &repetition_analysis/1)
    Enum.each(tags, &ascii_analysis/1)
    report_per_tag(tags)
  end

  defp default_dump_path do
    date = Date.utc_today() |> Date.to_iso8601()
    data_dir = Path.expand("../data", File.cwd!())
    Path.join(data_dir, "nfc_dump_#{date}.jsonl")
  end

  defp load_tags(path) do
    unless File.exists?(path) do
      raise "File not found: #{path}"
    end

    path
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.reject(&(&1 == ""))
    |> Stream.map(fn line ->
      case JSON.decode(line) do
        {:ok, tag} -> tag
        {:error, _} -> raise "Invalid JSON: #{String.slice(line, 0, 80)}..."
      end
    end)
    |> Enum.to_list()
  end

  defp blocks_to_binary(blocks) do
    blocks
    |> Enum.map(fn hex ->
      Base.decode16!(String.upcase(hex), case: :mixed)
    end)
    |> IO.iodata_to_binary()
  end

  # Payload length in bytes from block 0 (bytes 0-1 big-endian). Returns nil if block 0 missing or invalid.
  defp payload_length_from_header(blocks) do
    case Enum.at(blocks, 0) do
      nil -> nil
      hex when is_binary(hex) ->
        hex = String.pad_trailing(String.upcase(hex), 8, "0")
        bin = Base.decode16!(hex, case: :mixed)
        if byte_size(bin) >= 2 do
          <<hi::8, lo::8, _::binary>> = bin
          hi * 256 + lo
        else
          nil
        end
    end
  end

  # 0-based index of last block that contains payload. Uses header payload length when present; caps at last non-zero block in dump.
  defp last_payload_block_index(blocks) do
    case payload_length_from_header(blocks) do
      nil ->
        find_last_nonzero_block(blocks)
      len ->
        n_blocks = div(len + 3, 4)
        last_nonzero = find_last_nonzero_block(blocks)
        min(n_blocks, last_nonzero)
    end
  end

  defp find_last_nonzero_block(blocks) do
    blocks
    |> Enum.with_index()
    |> Enum.reject(fn {b, _} -> b == "00000000" or b == "0001" end)
    |> List.last()
    |> case do
      {_, i} -> i
      nil -> 0
    end
  end

  defp binary_to_hex_string(bin) do
    Base.encode16(bin, case: :lower)
  end

  defp compare_two(tag_a, tag_b) do
    uid_a = tag_a["uid"]
    uid_b = tag_b["uid"]
    blks_a = tag_a["blocks"]
    blks_b = tag_b["blocks"]

    IO.puts("=== Compare two tags ===")
    IO.puts("Tag A UID: #{uid_a}")
    IO.puts("Tag B UID: #{uid_b}\n")

    b0_a = Enum.at(blks_a, 0)
    b0_b = Enum.at(blks_b, 0)
    IO.puts("Block 0:  A=#{b0_a}  B=#{b0_b}")
    if String.ends_with?(b0_a, "010C") and String.ends_with?(b0_b, "010C") do
      IO.puts("         (both end with 010C — likely format/capability)\n")
    end

    len = max(length(blks_a), length(blks_b))
    first_different = Enum.find(1..(len - 1), fn i -> Enum.at(blks_a, i) != Enum.at(blks_b, i) end)
    last_data_a = last_payload_block_index(blks_a)
    last_data_b = last_payload_block_index(blks_b)
    payload_len_a = payload_length_from_header(blks_a)
    payload_len_b = payload_length_from_header(blks_b)
    IO.puts("First differing block index: #{first_different} (block 0 only shared)")
    IO.puts("Last data block (from header): A=#{last_data_a} (#{String.upcase(Enum.at(blks_a, last_data_a))})  B=#{last_data_b} (#{String.upcase(Enum.at(blks_b, last_data_b))})")
    IO.puts("Payload length (header bytes): A=#{payload_len_a || "?"} bytes  B=#{payload_len_b || "?"} bytes\n")

    IO.puts("\nFirst 16 bytes of payload only (blocks 1-2, skip block 0):")
    payload_a = Enum.drop(blks_a, 1) |> Enum.take(2) |> blocks_to_binary()
    payload_b = Enum.drop(blks_b, 1) |> Enum.take(2) |> blocks_to_binary()
    IO.puts("  A: #{binary_to_hex_string(payload_a)}")
    IO.puts("  B: #{binary_to_hex_string(payload_b)}")

    print_block0_and_block1_bytes(blks_a, blks_b, tag_a, tag_b)
    IO.puts("")
  end

  defp print_block0_and_block1_bytes(blks_a, blks_b, tag_a, tag_b) do
    b0_a = block_hex_to_bytes(Enum.at(blks_a, 0))
    b0_b = block_hex_to_bytes(Enum.at(blks_b, 0))
    b1_a = block_hex_to_bytes(Enum.at(blks_a, 1))
    b1_b = block_hex_to_bytes(Enum.at(blks_b, 1))
    item_a = Map.get(tag_a, "item", "A")
    item_b = Map.get(tag_b, "item", "B")
    IO.puts("\n--- Block 0 & 1 byte breakdown (candidates for type/capability e.g. color) ---")
    IO.puts("Block 0:  [#{item_a}] #{Enum.map_join(b0_a, " ", fn b -> "0x#{Integer.to_string(b, 16) |> String.pad_leading(2, "0")}" end)}  |  [#{item_b}] #{Enum.map_join(b0_b, " ", fn b -> "0x#{Integer.to_string(b, 16) |> String.pad_leading(2, "0")}" end)}")
    IO.puts("          byte0=len_hi byte1=len_lo( payload len ) byte2,3=0x010C")
    IO.puts("Block 1:  [#{item_a}] #{Enum.map_join(b1_a, " ", fn b -> "0x#{Integer.to_string(b, 16) |> String.pad_leading(2, "0")}" end)}  |  [#{item_b}] #{Enum.map_join(b1_b, " ", fn b -> "0x#{Integer.to_string(b, 16) |> String.pad_leading(2, "0")}" end)}")
    IO.puts("          byte0=record? byte1= type/capability? (differs: 0x#{Integer.to_string(Enum.at(b1_a, 1), 16)} vs 0x#{Integer.to_string(Enum.at(b1_b, 1), 16)})")
  end

  # Returns {payload_bin, payload_blocks_list} using header length when present; otherwise uses last non-zero block and drops last block (old behavior).
  defp payload_binary_and_blocks(tag) do
    blks = tag["blocks"]
    last_idx = last_payload_block_index(blks)
    payload_len = payload_length_from_header(blks)
    # Blocks 1..last_idx (inclusive) contain payload; last block may have padding
    payload_blocks = blks |> Enum.drop(1) |> Enum.take(last_idx)
    bin = blocks_to_binary(payload_blocks)
    bin = if payload_len && byte_size(bin) > payload_len do
      binary_part(bin, 0, payload_len)
    else
      bin
    end
    {bin, payload_blocks}
  end

  defp block_hex_to_bytes(hex) when is_binary(hex) do
    bin = Base.decode16!(String.pad_trailing(String.upcase(hex), 4, "0"), case: :mixed)
    for <<b <- bin>>, do: b
  end

  defp repetition_analysis(tag) do
    blks = tag["blocks"]
    last_idx = last_payload_block_index(blks)
    data_blocks = Enum.take(blks, last_idx + 1)
    {payload_bin, _payload_blocks} = payload_binary_and_blocks(tag)
    item = Map.get(tag, "item", tag["uid"])

    IO.puts("=== Repetition analysis: #{item} ===")

    # 1) Duplicate 4-byte blocks in data region (block 0 + payload blocks)
    block_counts = Enum.frequencies(data_blocks)
    dupes = Enum.filter(block_counts, fn {_blk, count} -> count > 1 end)
    if dupes == [] do
      IO.puts("  No duplicate 4-byte blocks in data region.")
    else
      IO.puts("  Duplicate blocks: #{inspect(dupes)}")
    end

    # 2) Repeated 4-byte sequences within payload (blocks 1 .. N-1)
    len = byte_size(payload_bin)
    if len >= 4 do
      four_byte_seqs = for i <- 0..(len - 4), do: binary_part(payload_bin, i, 4)
      freq_4 = Enum.frequencies(four_byte_seqs)
      repeated_4 = Enum.filter(freq_4, fn {_seq, count} -> count > 1 end) |> Enum.sort_by(fn {_, c} -> -c end)
      if repeated_4 == [] do
        IO.puts("  No repeated 4-byte sequence in payload.")
      else
        IO.puts("  Repeated 4-byte sequences in payload: #{length(repeated_4)}")
        Enum.take(repeated_4, 10) |> Enum.each(fn {seq, count} ->
          IO.puts("    #{Base.encode16(seq, case: :lower)}  ×#{count}")
        end)
      end
    end

    if len >= 8 do
      eight_byte_seqs = for i <- 0..(len - 8), do: binary_part(payload_bin, i, 8)
      freq_8 = Enum.frequencies(eight_byte_seqs)
      repeated_8 = Enum.filter(freq_8, fn {_seq, count} -> count > 1 end) |> Enum.sort_by(fn {_, c} -> -c end)
      if repeated_8 == [] do
        IO.puts("  No repeated 8-byte sequence in payload.")
      else
        IO.puts("  Repeated 8-byte sequences in payload: #{length(repeated_8)}")
        Enum.take(repeated_8, 5) |> Enum.each(fn {seq, count} ->
          IO.puts("    #{Base.encode16(seq, case: :lower)}  ×#{count}")
        end)
      end
    end
    IO.puts("")
  end

  defp ascii_analysis(tag) do
    {payload_bin, _} = payload_binary_and_blocks(tag)
    item = Map.get(tag, "item", tag["uid"])

    IO.puts("=== ASCII / printable check: #{item} ===")
    len = byte_size(payload_bin)
    bytes = for <<b <- payload_bin>>, do: b
    printable = Enum.count(bytes, fn b -> b >= 0x20 and b <= 0x7E end)
    pct = if len > 0, do: Float.round(100.0 * printable / len, 1), else: 0
    IO.puts("  Payload bytes: #{len}  |  Printable (0x20-0x7E): #{printable} (#{pct}%)")

    runs = find_printable_runs(bytes)
    if runs == [] do
      IO.puts("  No runs of 2+ consecutive printable ASCII.")
    else
      IO.puts("  Runs of 2+ printable ASCII:")
      Enum.take(runs, 15) |> Enum.each(fn {start, run} ->
        str = for b <- run, do: <<b>>
        IO.puts("    offset #{start}: #{inspect(IO.iodata_to_binary(str))}")
      end)
    end

    IO.puts("  First 64 bytes (dot = non-printable):")
    preview = binary_part(payload_bin, 0, min(64, len))
    line = for <<b <- preview>> do
      if b >= 0x20 and b <= 0x7E, do: <<b>>, else: "."
    end
    IO.puts("    #{IO.iodata_to_binary(line)}")
    IO.puts("")
  end

  defp find_printable_runs(bytes) do
    {acc, run_start, run_buf} =
      Enum.with_index(bytes)
      |> Enum.reduce({[], nil, []}, fn
        {b, i}, {acc, run_start, run_buf} when b >= 0x20 and b <= 0x7E ->
          start = run_start || i
          {acc, start, [b | run_buf]}
        _, {acc, run_start, run_buf} ->
          if length(run_buf) >= 2 do
            {[{run_start, Enum.reverse(run_buf)} | acc], nil, []}
          else
            {acc, nil, []}
          end
      end)
    # flush final run
    if length(run_buf) >= 2 do
      [{run_start, Enum.reverse(run_buf)} | acc]
    else
      acc
    end
    |> Enum.reverse()
  end

  defp report_per_tag(tags) do
    IO.puts("=== Per-tag summary ===")
    Enum.with_index(tags, 1)
    |> Enum.each(fn {tag, idx} ->
      blks = tag["blocks"]
      last = last_payload_block_index(blks)
      payload_len = payload_length_from_header(blks)
      payload_blocks = max(0, last)
      item = Map.get(tag, "item", "")
      item_str = if item == "", do: "", else: "  item=#{item}"
      len_str = if payload_len, do: "  payload=#{payload_len} bytes (#{payload_blocks} blocks)", else: "  payload=#{payload_blocks} blocks"
      IO.puts("  #{idx}. UID #{tag["uid"]}#{item_str}#{len_str}")
    end)
  end
end
