defmodule NfcDecrypt do
  @moduledoc """
  ARCHIVED — AES-CCM / generic cipher experiments for LEGO Smart Tag payloads.

  ⚠ TAGS USE GRAIN-128A, NOT AES-CCM ⚠

  The AES-CCM functions in the EM9305 firmware are for BrickNet PAwR session
  encryption and EM9305↔ASIC mutual authentication — NOT tag decryption.
  Tag data is encrypted with Grain-128A (ISO/IEC 29167-13) by the DA000001-01
  ASIC. The EM9305 never sees encrypted tag data.

  For active tag decryption work, see:
    - GrainExperiments (mac_capture/lib/grain_experiments.ex)
    - Grain128a        (mac_capture/lib/grain128a.ex)

  This module is retained for:
    - BrickNet AES-CCM analysis (if investigating brick-to-brick encryption)
    - Historical reference of prior decryption strategies

  Tag EEPROM layout:
    Bytes 0-1:  Payload length (big-endian)
    Bytes 2-3:  0x01 0x0C (fixed, total tag capacity = 268 bytes)
    Byte  4:    0x01 (format version)
    Bytes 5-16: Per-content IV (96 bits, 12 bytes) for Grain-128A
    Byte  17+:  Grain-128A ciphertext

  Run with:
    mix run -e "NfcDecrypt.run()"
    mix run -e "NfcDecrypt.run(\"data/hardware_md_tag_dumps.jsonl\")"
    mix run -e "NfcDecrypt.run(nil, aes_bruteforce_tries: 50_000)"
    mix run -e "NfcDecrypt.run(nil, aes_bruteforce_tries: 0)"
    mix run -e "NfcDecrypt.run_v2()"
    mix run -e "NfcDecrypt.run_aes_ccm()"                         # AES-CCM — BrickNet analysis only
  """
  import Bitwise

  @cleartext_header_size 5
  # Event type magics at TLV offset 4 (uint32 LE). From firmware v2.29.1 / node-smartplay HARDWARE.md.
  @identity_event_magic <<0xD1, 0x4E, 0xE2, 0xA7>>   # 0xA7E24ED1 Identity / alias / presence
  @item_event_magic <<0x13, 0xA1, 0xBD, 0x0B>>       # 0x0BBDA113 Item (tile)
  @play_cmd_magic <<0xDC, 0x12, 0x23, 0x81>>        # 0x812312DC Play command
  @distributed_play_magic <<0x84, 0x0D, 0x4A, 0x81>> # 0x814A0D84 Distributed play (PAwR)
  @status_position_magic <<0x71, 0x71, 0xB7, 0xE3>> # 0xE3B77171 Status/position event

  @all_event_magics [
    @identity_event_magic,
    @item_event_magic,
    @play_cmd_magic,
    @distributed_play_magic,
    @status_position_magic
  ]

  @tea_delta 0x9E3779B9
  @mask32 0xFFFFFFFF

  # Skip test/modified tag copies: item/label contains [FAIL] or [RED FLASH]
  defp skip_test_tag?(tag) do
    label = Map.get(tag, "item", tag["uid"] || "") |> String.downcase()
    String.contains?(label, "[fail]") or String.contains?(label, "[red flash]")
  end

  defp drop_test_tags(tags) do
    Enum.reject(tags, &skip_test_tag?/1)
  end

  @doc """
  Backfill missing "category" field in JSONL using name-based inference (identity/item/unknown).
  Use when re-processing old dumps that don't have category set.

  Usage:
    mix run -e "NfcDecrypt.backfill_category_jsonl(\\\"data\\\")"
    mix run -e "NfcDecrypt.backfill_category_jsonl(\\\"data/nfc_dump_2026-03-12.jsonl\\\")"
  """
  def backfill_category_jsonl(path_or_dir) do
    paths =
      if File.dir?(path_or_dir) do
        Path.wildcard(Path.join(path_or_dir, "*.jsonl")) |> Enum.sort()
      else
        if File.exists?(path_or_dir), do: [path_or_dir], else: []
      end

    if paths == [] do
      IO.puts("No JSONL file(s) found at #{path_or_dir}")
      :ok
    else
      Enum.each(paths, &backfill_one_jsonl/1)
    end
  end

  defp backfill_one_jsonl(path) do
    lines =
      path
      |> File.stream!()
      |> Stream.map(&String.trim/1)
      |> Stream.reject(&(&1 == ""))
      |> Enum.map(fn line ->
        case JSON.decode(line) do
          {:ok, tag} when is_map(tag) ->
            tag =
              if Map.has_key?(tag, "category") and tag["category"] != nil and tag["category"] != "" do
                tag
              else
                cat = tag_category_from_item(tag)
                Map.put(tag, "category", Atom.to_string(cat))
              end
            JSON.encode!(tag)
          _ ->
            line
        end
      end)

    File.write!(path, Enum.join(lines, "\n") <> "\n")
    IO.puts("Backfilled category in #{path} (#{length(lines)} lines)")
  end

  @doc "ARCHIVED: generic cipher experiments. Tags use Grain-128A — see GrainExperiments."
  def run(jsonl_path \\ nil, opts \\ []) do
    {paths, raw} =
      if jsonl_path do
        path = jsonl_path
        {[path], load_tags(path)}
      else
        data_dir = resolve_data_dir()
        paths = Path.wildcard(Path.join(data_dir, "*.jsonl")) |> Enum.sort()
        raw = Enum.flat_map(paths, &load_tags/1)
        {paths, raw}
      end

    tags = drop_test_tags(raw)
    skipped = length(raw) - length(tags)
    if skipped > 0, do: IO.puts("Skipped #{skipped} test tag(s) ([FAIL] / [RED FLASH])\n")
    if length(paths) == 1 do
      IO.puts("Loaded #{length(tags)} tag(s) from #{hd(paths)}\n")
    else
      IO.puts("Loaded #{length(tags)} tag(s) from #{length(paths)} file(s): #{Enum.join(paths, ", ")}\n")
    end

    # Dedupe by payload so we don't double-count identical tags (e.g. two Lukes)
    unique = dedupe_by_payload(tags)
    IO.puts("Unique payloads: #{length(unique)} (by content)\n")

    Enum.each(unique, fn tag ->
      try_single_byte_xor(tag)
    end)

    if length(unique) >= 2 do
      [a | rest] = unique
      b = List.first(rest)
      xor_two_payloads(a, b)
      # One more pair (e.g. Identity vs Item)
      if length(unique) >= 3 do
        xor_two_payloads(List.first(unique), List.last(unique))
      end
    end

    # Try repeating 2-byte key brute (report best by printable %)
    IO.puts("\n=== Best 2-byte repeating key (first tag) ===")
    if length(unique) >= 1 do
      try_two_byte_key(List.first(unique))
    end

    # TLV known-plaintext: assume decrypted = [type_id:2 LE][content_length:2 LE][payload]
    IO.puts("\n=== TLV known-plaintext (stream cipher: 4-byte key from first 4 bytes) ===")
    Enum.each(unique, &try_tlv_known_plaintext/1)

    # (1) TLV plaintext variants: content_length = payload_len-4, payload_len-8, payload_len; block type 0,1,2
    IO.puts("\n=== TLV variants (content_len × block_type) ===")
    Enum.each(unique, &try_tlv_variants/1)

    # (2) AES-CCM with candidate keys (firmware uses CCM, not ECB)
    if length(unique) >= 1 do
      keys = load_all_candidate_keys() ++ tag_derived_candidate_keys(unique)
      IO.puts("\n=== AES-128-CCM with candidate keys (#{length(keys)} keys, embedded-nonce then header-nonce) ===")
      hit = try_ccm_embedded_nonce(unique, keys)
      if !hit, do: try_ccm_header_nonce(unique, keys)
    end

    # (2b) AES-CCM brute-force with random keys (payload is CCM, not ECB; same option name for compatibility)
    num_rand = opts[:aes_bruteforce_tries] || 100_000
    if num_rand > 0 and length(unique) >= 1 do
      IO.puts("\n=== AES-128-CCM brute-force (#{num_rand} random 16-byte keys, embedded-nonce then header-nonce) ===")
      try_ccm_random_keys(unique, num_rand)
    end
    num_str = opts[:aes_bruteforce_strings] || 0
    if num_str > 0 and length(unique) >= 1 do
      IO.puts("\n=== AES-128-ECB brute-force (#{num_str} random string keys, validate on ≥4 tags) ===")
      try_aes_ecb_bruteforce_strings(List.first(unique), num_str, unique)
    end

    # (3) Iterate type_id (0x0000..0x0FFF) to find plausible next TLV
    IO.puts("\n=== TLV type_id scan (find type_id s.t. bytes 4-7 look like TLV) ===")
    Enum.each(unique, &try_tlv_type_id_scan/1)

    run_v2_analysis(unique, opts)
  end

  @doc "ARCHIVED: V2 analysis with corrected offset. Tags use Grain-128A — see GrainExperiments."
  def run_v2(jsonl_path \\ nil, _opts \\ []) do
    paths = if jsonl_path do
      [jsonl_path]
    else
      data_dir = resolve_data_dir()
      Path.wildcard(Path.join(data_dir, "*.jsonl"))
    end
    tags = Enum.flat_map(paths, &load_tags/1)
    raw_count = length(tags)
    tags = drop_test_tags(tags)
    skipped = raw_count - length(tags)
    if skipped > 0, do: IO.puts("Skipped #{skipped} test tag(s) ([FAIL] / [RED FLASH])\n")
    IO.puts("Loaded #{length(tags)} tag(s) from #{length(paths)} file(s): #{Enum.join(paths, ", ")}\n")
    unique = dedupe_by_payload(tags)
    IO.puts("Unique payloads: #{length(unique)} (by content)\n")
    run_v2_analysis(unique, [])
  end

  defp resolve_data_dir do
    cwd = File.cwd!()
    if String.ends_with?(cwd, "mac_capture"), do: Path.expand("../data", cwd), else: Path.join(cwd, "data")
  end

  defp run_v2_analysis(unique, _opts) do
    IO.puts("\n" <> String.duplicate("=", 70))
    IO.puts("=== V2 ANALYSIS (encrypted region starts at byte 5, not byte 4) ===")
    IO.puts(String.duplicate("=", 70))

    Enum.each(unique, fn tag ->
      enc = encrypted_binary(tag)
      IO.puts("  #{tag_label(tag)}: #{byte_size(enc)} encrypted bytes, category=#{tag_category(tag)}")
    end)
    IO.puts("")

    IO.puts("=== Entropy analysis (encrypted region) ===")
    Enum.each(unique, &entropy_analysis/1)

    IO.puts("\n=== Known-plaintext: event type magic recovery (stream cipher test) ===")
    try_known_plaintext_magic(unique)

    IO.puts("\n=== MAC length inference (enc_len - 4/8/16 per tag) ===")
    mac_length_inference(unique)

    IO.puts("\n=== Keystream extended (bytes 8-15: assume zero padding) ===")
    try_keystream_extended(unique)

    IO.puts("\n=== Constrain P[0:3] (type_id + content_len → K[0:3] consistency) ===")
    try_constrain_p0_p3(unique)

    IO.puts("\n=== TEA / XTEA with candidate keys (cross-tag validated) ===")
    try_tea_xtea_all(unique)

    IO.puts("\n=== AES-128 CBC/CTR/CFB/OFB with candidate keys ===")
    try_aes_modes_all(unique)

    IO.puts("\n=== SPECK / SIMON with candidate keys (cross-tag validated) ===")
    try_speck_simon_all(unique)

    IO.puts("\n=== Relaxed scoring scan (all ciphers, heuristic validation) ===")
    try_relaxed_scan(unique)

    IO.puts("\n=== Differential analysis (pairwise XOR, byte distribution) ===")
    differential_analysis(unique)

    IO.puts("\n=== Compression / alternative-encoding hypothesis ===")
    compression_analysis(unique)
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

  defp dedupe_by_payload(tags) do
    tags
    |> Enum.uniq_by(fn tag ->
      {tag["blocks"] |> Enum.take(last_payload_block_index(tag["blocks"]) + 1)}
    end)
  end

  defp blocks_to_binary(blocks) do
    blocks
    |> Enum.map(fn hex -> Base.decode16!(String.upcase(hex), case: :mixed) end)
    |> IO.iodata_to_binary()
  end

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

  defp last_payload_block_index(blocks) do
    case payload_length_from_header(blocks) do
      nil -> find_last_nonzero(blocks)
      len ->
        n_blocks = div(len + 3, 4)
        min(n_blocks, find_last_nonzero(blocks))
    end
  end

  defp find_last_nonzero(blocks) do
    blocks
    |> Enum.with_index()
    |> Enum.reject(fn {b, _} -> b == "00000000" or b == "0001" end)
    |> List.last()
    |> case do
      {_, i} -> i
      nil -> 0
    end
  end

  defp payload_binary(tag) do
    blocks = tag["blocks"]
    last_idx = last_payload_block_index(blocks)
    payload_len = payload_length_from_header(blocks)
    payload_blocks = blocks |> Enum.drop(1) |> Enum.take(last_idx)
    bin = blocks_to_binary(payload_blocks)
    if payload_len && byte_size(bin) > payload_len do
      binary_part(bin, 0, payload_len)
    else
      bin
    end
  end

  defp encrypted_binary(tag) do
    blocks = tag["blocks"]
    last_idx = last_payload_block_index(blocks)
    payload_len = payload_length_from_header(blocks)
    all_data_blocks = blocks |> Enum.take(last_idx + 1)
    bin = blocks_to_binary(all_data_blocks)
    enc_len = if payload_len, do: payload_len - @cleartext_header_size, else: byte_size(bin) - @cleartext_header_size
    if enc_len > 0 and byte_size(bin) > @cleartext_header_size do
      binary_part(bin, @cleartext_header_size, min(enc_len, byte_size(bin) - @cleartext_header_size))
    else
      <<>>
    end
  end

  defp tag_category(tag) do
    case Map.get(tag, "category") |> normalize_category_field() do
      nil -> tag_category_from_item(tag)
      cat -> cat
    end
  end

  defp normalize_category_field(nil), do: nil
  defp normalize_category_field(""), do: nil
  defp normalize_category_field(s) when is_binary(s) do
    case String.downcase(String.trim(s)) do
      "identity" -> :identity
      "item" -> :item
      "unknown" -> :unknown
      _ -> nil
    end
  end

  # Fallback for JSONL without "category": infer from "item" label (legacy / backfill).
  defp tag_category_from_item(tag) do
    item = (Map.get(tag, "item", "") || "") |> String.downcase()
    cond do
      String.contains?(item, "(identity") -> :identity
      String.contains?(item, "luke") or String.contains?(item, "vader") or
        String.contains?(item, "palpatine") or String.contains?(item, "leia") or
        String.contains?(item, "r2-d2") or String.contains?(item, "yoda") -> :identity
      String.contains?(item, "(item") or String.contains?(item, "lightsaber") or
        String.contains?(item, "x-wing") or String.contains?(item, "tie ") -> :item
      true -> :unknown
    end
  end

  defp expected_event_magic(tag) do
    case tag_category(tag) do
      :item -> @item_event_magic
      :identity -> @identity_event_magic
      :unknown -> nil
    end
  end

  defp tag_label(tag), do: Map.get(tag, "item", tag["uid"])

  defp xor_bytes(bin, key_byte) do
    for <<b <- bin>>, do: Bitwise.bxor(b, key_byte)
  end

  defp xor_bytes_with_key(bin, key) when is_binary(key) do
    key_len = byte_size(key)
    bin
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {b, i} -> Bitwise.bxor(b, :binary.at(key, rem(i, key_len))) end)
  end

  defp printable_or_zero_ratio(bytes) do
    n = length(bytes)
    if n == 0 do
      0.0
    else
      count = Enum.count(bytes, fn b -> b == 0 or (b >= 0x20 and b <= 0x7E) end)
      count / n
    end
  end

  defp trailing_zeros_count(bytes) do
    bytes
    |> Enum.reverse()
    |> Enum.take_while(&(&1 == 0))
    |> length()
  end

  # Score bytes 4-7 of "decrypted" as next TLV header: type_ok (bits 12-13 in 0,1,2), len in 0..max_len
  defp score_tlv_next(bytes, max_len) do
    next_hi = Enum.at(bytes, 5) || 0
    next_len_lo = Enum.at(bytes, 6) || 0
    next_len_hi = Enum.at(bytes, 7) || 0
    next_len = next_len_lo + bsl(next_len_hi, 8)
    type_ok = (next_hi &&& 0x30) in [0, 0x10, 0x20]
    len_ok = next_len in 0..max_len
    {type_ok, len_ok, next_len}
  end

  defp try_single_byte_xor(tag) do
    payload = payload_binary(tag)
    item = Map.get(tag, "item", tag["uid"])
    len = byte_size(payload)

    candidates =
      for key <- 0..255 do
        dec = xor_bytes(payload, key)
        ratio = printable_or_zero_ratio(dec)
        trail = trailing_zeros_count(dec)
        score = ratio * 100 + min(trail / 4, 1) * 20
        {key, dec, ratio, trail, score}
      end
      |> Enum.sort_by(fn {_, _, _, _, s} -> -s end)
      |> Enum.take(5)

    # Only print if at least one key gives something interesting (high ratio or trailing zeros)
    best = List.first(candidates)
    if best do
      {_key, _dec, ratio, trail, _} = best
      if ratio > 0.5 or trail >= 2 do
        IO.puts("=== #{item} (payload #{len} B) ===")
        IO.puts("  Top single-byte XOR keys (by printable+trailing score):")
        for {key, dec, r, t, _} <- candidates do
          preview = dec |> Enum.take(32) |> Enum.map(&Integer.to_string(&1, 16)) |> Enum.join(" ")
          IO.puts("    key 0x#{Integer.to_string(key, 16) |> String.pad_leading(2, "0")}: ratio=#{Float.round(r, 3)} trail_zeros=#{t}  first32=#{preview}")
        end
        IO.puts("")
      end
    end
  end

  defp xor_two_payloads(tag_a, tag_b) do
    pa = payload_binary(tag_a)
    pb = payload_binary(tag_b)
    len = min(byte_size(pa), byte_size(pb))
    xor_result = for i <- 0..(len - 1), do: Bitwise.bxor(binary_part(pa, i, 1) |> :binary.first(), binary_part(pb, i, 1) |> :binary.first())

    item_a = Map.get(tag_a, "item", tag_a["uid"])
    item_b = Map.get(tag_b, "item", tag_b["uid"])

    IO.puts("=== XOR of two payloads (C1⊕C2) ===")
    IO.puts("  #{item_a}")
    IO.puts("  vs #{item_b}")
    IO.puts("  Length: #{len} bytes (min of two)")
    hex = xor_result |> Enum.take(64) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
    IO.puts("  First 64 bytes (hex): #{hex}")
    # If first bytes are same structure (e.g. type byte), XOR gives 0 there
    leading_zeros = xor_result |> Enum.take_while(&(&1 == 0)) |> length()
    IO.puts("  Leading zero bytes: #{leading_zeros}")
    IO.puts("")
  end

  # Assumes decrypted payload starts with TLV: [type_id:2 LE][content_length:2 LE][payload].
  # We assume first block is "header" (type_id in 0x0000..0x0FFF) and content_length = payload_len - 4.
  # Then key_stream[0..3] = ciphertext[0..3] XOR plaintext[0..3]. Decrypt rest with 4-byte repeating key.
  defp try_tlv_known_plaintext(tag) do
    payload = payload_binary(tag)
    payload_len = byte_size(payload)
    if payload_len < 4 do
      IO.puts("  (skip: payload < 4 bytes)")
    else
      content_len = payload_len - 4
      pt = <<0x00::16-little, content_len::16-little>>
      key_4 = for i <- 0..3, do: Bitwise.bxor(binary_part(payload, i, 1) |> :binary.first(), :binary.at(pt, i))
      dec = for i <- 0..(payload_len - 1), do: Bitwise.bxor(binary_part(payload, i, 1) |> :binary.first(), Enum.at(key_4, rem(i, 4)))
      next_hi = Enum.at(dec, 5) || 0
      next_len_lo = Enum.at(dec, 6) || 0
      next_len_hi = Enum.at(dec, 7) || 0
      next_len = next_len_lo + bsl(next_len_hi, 8)
      type_ok = (next_hi &&& 0x30) in [0, 0x10, 0x20]
      len_ok = next_len in 0..300
      ratio = printable_or_zero_ratio(dec)
      score = ratio * 100 + (if type_ok, do: 10, else: 0) + (if len_ok, do: 15, else: 0)
      item = Map.get(tag, "item", tag["uid"])
      key_hex = key_4 |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
      IO.puts("  #{item}: key_4=#{key_hex}  next_tlv_len=#{next_len}  type_ok=#{type_ok}  len_ok=#{len_ok}  ratio=#{Float.round(ratio, 3)} score=#{Float.round(score, 1)}")
      if score > 45 or ratio > 0.5 do
        preview = dec |> Enum.take(24) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
        IO.puts("    decrypted first 24: #{preview}")
      end
    end
  end

  # Try content_length in [payload_len-4, payload_len-8, payload_len] and block type 0, 1, 2
  defp try_tlv_variants(tag) do
    payload = payload_binary(tag)
    payload_len = byte_size(payload)
    item = Map.get(tag, "item", tag["uid"])
    if payload_len < 4 do
      IO.puts("  #{item}: skip (payload < 4)")
    else
      content_len_opts = [payload_len - 4, max(0, payload_len - 8), payload_len] |> Enum.uniq()
      block_types = [0x0000, 0x1000, 0x2000]
      results =
        for type_id <- block_types,
            content_len <- content_len_opts,
            content_len >= 0 do
          pt = <<type_id::16-little, content_len::16-little>>
          key_4 = for i <- 0..3, do: Bitwise.bxor(binary_part(payload, i, 1) |> :binary.first(), :binary.at(pt, i))
          dec = for i <- 0..(payload_len - 1), do: Bitwise.bxor(binary_part(payload, i, 1) |> :binary.first(), Enum.at(key_4, rem(i, 4)))
          {type_ok, len_ok, next_len} = score_tlv_next(dec, 250)
          ratio = printable_or_zero_ratio(dec)
          score = ratio * 100 + (if type_ok, do: 10, else: 0) + (if len_ok, do: 20, else: 0)
          {type_id, content_len, key_4, dec, type_ok, len_ok, next_len, ratio, score}
        end
      best = Enum.max_by(results, fn {_, _, _, _, _, _, _, _, s} -> s end)
      {_tid, _clen, key_4, _dec, type_ok, len_ok, next_len, _ratio, score} = best
      key_hex = key_4 |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
      IO.puts("  #{item}: best type_id=0x#{Integer.to_string(elem(best, 0), 16)} content_len=#{elem(best, 1)} key_4=#{key_hex} next_len=#{next_len} type_ok=#{type_ok} len_ok=#{len_ok} score=#{Float.round(score, 1)}")
      hits = Enum.filter(results, fn {_, _, _, _, to, lo, _, _, _} -> to and lo end)
      if hits != [] do
        IO.puts("    >>> len_ok+type_ok hits: #{length(hits)}")
        for {tid, clen, _, _, _, _, nl, _, _} <- Enum.take(hits, 5) do
          IO.puts("       type_id=0x#{Integer.to_string(tid, 16)} content_len=#{clen} next_tlv_len=#{nl}")
        end
      end
    end
  end

  defp pad16(bin) when is_binary(bin) do
    len = byte_size(bin)
    if len >= 16 do
      binary_part(bin, 0, 16)
    else
      bin <> :binary.copy(<<0>>, 16 - len)
    end
  end

  # For a key, decrypt first 16 bytes of each payload; return {count where type_ok+len_ok, total_with_16_bytes}.
  # (Used by try_aes_ecb_bruteforce_strings for cross-tag validation.)
  defp validate_aes_key_on_payloads(key, all_payloads) do
    result =
      Enum.reduce(all_payloads, 0, fn pl, acc ->
        if byte_size(pl) >= 16 do
          block0 = binary_part(pl, 0, 16)
          try do
            dec = :crypto.crypto_one_time(:aes_128_ecb, key, block0, false)
            dec_list = :binary.bin_to_list(dec)
            {type_ok, len_ok, _} = score_tlv_next(dec_list ++ List.duplicate(0, 8), 300)
            if type_ok and len_ok, do: acc + 1, else: acc
          rescue
            _ -> acc
          end
        else
          acc
        end
      end)
    total = Enum.count(all_payloads, fn pl -> byte_size(pl) >= 16 end)
    {result, total}
  end

  defp update_top5(current, {_key, _dec, _ratio} = elem, max) do
    sorted = [elem | current] |> Enum.sort_by(fn {_, _, r} -> r end, :desc) |> Enum.take(max)
    sorted
  end

  @alnum ~c"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

  defp try_aes_ecb_bruteforce_strings(tag, num_tries, all_tags) do
    payload = payload_binary(tag)
    item = Map.get(tag, "item", tag["uid"])
    all_payloads = Enum.map(all_tags, &payload_binary/1)
    min_validated = min(4, length(all_payloads))

    if byte_size(payload) < 16 do
      IO.puts("  #{item}: skip (payload < 16)")
    else
      block0 = binary_part(payload, 0, 16)
      len_al = length(@alnum)
      {raw_hits, validated_hits, top5} =
        Enum.reduce(1..num_tries, {[], [], []}, fn _i, {raw_hits, validated_hits, top5} ->
          len = 4 + :rand.uniform(13)
          key_str = for _ <- 1..len, do: Enum.at(@alnum, :rand.uniform(len_al) - 1)
          key = pad16(IO.iodata_to_binary(key_str))
          try do
            dec = :crypto.crypto_one_time(:aes_128_ecb, key, block0, false)
            dec_list = :binary.bin_to_list(dec)
            {type_ok, len_ok, next_len} = score_tlv_next(dec_list ++ List.duplicate(0, 8), 300)
            ratio = printable_or_zero_ratio(dec_list)
            top5 = update_top5(top5, {key_str, dec_list, ratio}, 5)
            if type_ok and len_ok do
              {n, _} = validate_aes_key_on_payloads(key, all_payloads)
              validated = if n >= min_validated, do: [{key_str, dec_list, next_len, n} | validated_hits], else: validated_hits
              {[{key_str, dec_list, next_len} | raw_hits], validated, top5}
            else
              {raw_hits, validated_hits, top5}
            end
          rescue
            _ -> {raw_hits, validated_hits, top5}
          end
        end)

      n_raw = length(raw_hits)
      n_val = length(validated_hits)
      valid_note = if length(all_tags) < 4, do: " (only #{length(all_tags)} tag(s), require all)", else: " (≥#{min_validated} tags)"
      IO.puts("  #{item}: tried #{num_tries} random string keys (4–16 chars) → #{n_raw} raw TLV-like hits, #{n_val} validated#{valid_note}")
      if validated_hits != [] do
        for {key_str, dec, nl, n} <- Enum.take(validated_hits, 5) do
          key_s = IO.iodata_to_binary(key_str)
          hex = dec |> Enum.take(8) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
          IO.puts("    >>> key=#{inspect(key_s)} next_len=#{nl} validated_on=#{n}/#{length(all_tags)} first8=#{hex}")
        end
        if length(validated_hits) > 5, do: IO.puts("    ... and #{length(validated_hits) - 5} more")
      else
        if raw_hits != [] do
          IO.puts("    (no key passed cross-tag validation; #{n_raw} false positives filtered out)")
        else
          best_ratio = if top5 == [], do: 0.0, else: elem(List.first(top5), 2)
          IO.puts("    no TLV-like hits; top printable ratio: #{Float.round(best_ratio, 4)}")
          for {key_str, dec, ratio} <- Enum.take(top5, 3) do
            key_s = IO.iodata_to_binary(key_str)
            hex = dec |> Enum.take(8) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
            IO.puts("       key=#{inspect(key_s)} ratio=#{Float.round(ratio, 4)} first8=#{hex}")
          end
        end
      end
    end
  end

  defp trim_null(bin) do
    case :binary.split(bin, <<0>>) do
      [head, _] -> head
      [head] -> head
    end
  end

  defp try_tlv_type_id_scan(tag) do
    payload = payload_binary(tag)
    payload_len = byte_size(payload)
    item = Map.get(tag, "item", tag["uid"])
    if payload_len < 8 do
      IO.puts("  #{item}: skip (payload < 8)")
    else
      content_len = payload_len - 4
      hits =
        for type_id <- 0..0x0FFF do
          pt = <<type_id::16-little, content_len::16-little>>
          key_4 = for i <- 0..3, do: Bitwise.bxor(binary_part(payload, i, 1) |> :binary.first(), :binary.at(pt, i))
          dec = for i <- 0..(min(7, payload_len - 1)), do: Bitwise.bxor(binary_part(payload, i, 1) |> :binary.first(), Enum.at(key_4, rem(i, 4)))
          {type_ok, len_ok, next_len} = score_tlv_next(dec ++ List.duplicate(0, 8), 250)
          if type_ok and len_ok, do: {type_id, key_4, next_len}, else: nil
        end
        |> Enum.reject(&is_nil/1)

      IO.puts("  #{item}: type_id scan 0x0000..0x0FFF → #{length(hits)} hits (type_ok+len_ok)")
      if hits != [] do
        for {tid, key_4, nl} <- Enum.take(hits, 10) do
          key_hex = key_4 |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
          IO.puts("    type_id=0x#{Integer.to_string(tid, 16)} key_4=#{key_hex} next_tlv_len=#{nl}")
        end
        if length(hits) > 10, do: IO.puts("    ... and #{length(hits) - 10} more")
      end
    end
  end

  defp try_two_byte_key(tag) do
    payload = payload_binary(tag)

    results =
      for k0 <- 0..255, k1 <- 0..255 do
        key = <<k0, k1>>
        dec = xor_bytes_with_key(payload, key)
        ratio = printable_or_zero_ratio(dec)
        trail = trailing_zeros_count(dec)
        score = ratio * 100 + min(trail / 4, 1) * 15
        {key, dec, ratio, score}
      end

    best = if results == [], do: nil, else: Enum.max_by(results, fn {_, _, _, s} -> s end)

    case best do
      {key, dec, ratio, _} when ratio > 0.3 ->
        IO.puts("  Best 2-byte key (hex): #{Base.encode16(key, case: :lower)}  printable_or_zero_ratio=#{Float.round(ratio, 3)}")
        preview = dec |> Enum.take(48) |> Enum.map(fn b -> if b >= 0x20 and b <= 0x7E, do: <<b>>, else: "." end) |> IO.iodata_to_binary()
        IO.puts("  First 48 bytes (printable or .): #{preview}")
      _ ->
        IO.puts("  No 2-byte key gave clearly structured output (best ratio < 0.3).")
    end
  end

  # ---------------------------------------------------------------------------
  # V2: Corrected analysis functions (encrypted region = byte 5+)
  # ---------------------------------------------------------------------------

  defp u32(x), do: x &&& @mask32

  defp parse_u32_pair(<<a::32-big, b::32-big>>, :big), do: {a, b}
  defp parse_u32_pair(<<a::32-little, b::32-little>>, :little), do: {a, b}

  defp parse_u32_list(<<a::32-big, b::32-big, c::32-big, d::32-big>>, :big), do: [a, b, c, d]
  defp parse_u32_list(<<a::32-little, b::32-little, c::32-little, d::32-little>>, :little), do: [a, b, c, d]

  defp encode_u32_pair(a, b, :big), do: <<a::32-big, b::32-big>>
  defp encode_u32_pair(a, b, :little), do: <<a::32-little, b::32-little>>

  defp ror32(x, n), do: u32(bor(x >>> n, u32(x <<< (32 - n))))
  defp rol32(x, n), do: u32(bor(u32(x <<< n), x >>> (32 - n)))
  defp not32(x), do: bxor(x, @mask32)

  @mask64 0xFFFFFFFFFFFFFFFF
  defp u64(x), do: x &&& @mask64
  defp ror64(x, n), do: u64(bor(x >>> n, u64(x <<< (64 - n))))
  defp rol64(x, n), do: u64(bor(u64(x <<< n), x >>> (64 - n)))

  defp parse_u64_pair(<<a::64-big, b::64-big>>, :big), do: {a, b}
  defp parse_u64_pair(<<a::64-little, b::64-little>>, :little), do: {a, b}
  defp encode_u64_pair(a, b, :big), do: <<a::64-big, b::64-big>>
  defp encode_u64_pair(a, b, :little), do: <<a::64-little, b::64-little>>

  # --- TLV + event magic validation ---

  defp validate_tlv_magic(dec_bytes, tag) when is_list(dec_bytes) and length(dec_bytes) >= 8 do
    type_hi = Enum.at(dec_bytes, 1)
    len_lo = Enum.at(dec_bytes, 2)
    len_hi = Enum.at(dec_bytes, 3)
    magic_bytes = Enum.slice(dec_bytes, 4, 4) |> IO.iodata_to_binary()

    block_type = (type_hi &&& 0x30) |> bsr(4)
    block_type_ok = block_type in [0, 1, 2]
    upper_ok = (type_hi &&& 0xC0) == 0

    enc_len = byte_size(encrypted_binary(tag))
    content_len = len_lo + bsl(len_hi, 8)
    len_ok = content_len > 0 and content_len <= enc_len and content_len >= div(enc_len, 2)

    expected = expected_event_magic(tag)
    magic_ok = if expected do
      magic_bytes == expected
    else
      magic_bytes in @all_event_magics
    end

    pass = block_type_ok and upper_ok and len_ok and magic_ok
    {if(pass, do: :pass, else: :fail),
     %{block_type: block_type, block_type_ok: block_type_ok, upper_ok: upper_ok,
       content_len: content_len, len_ok: len_ok, magic_ok: magic_ok,
       category: tag_category(tag)}}
  end

  defp validate_tlv_magic(_dec_bytes, _tag), do: {:fail, %{}}

  # --- TEA decryption (64 Feistel rounds, 8-byte blocks, 128-bit key) ---

  defp tea_decrypt_block(block8, key16, endian) when byte_size(block8) == 8 and byte_size(key16) == 16 do
    {v0, v1} = parse_u32_pair(block8, endian)
    [k0, k1, k2, k3] = parse_u32_list(key16, endian)
    sum = u32(@tea_delta * 32)

    {v0, v1, _} = Enum.reduce(1..32, {v0, v1, sum}, fn _, {v0, v1, sum} ->
      rhs1 = bxor(bxor(u32(u32(v0 <<< 4) + k2), u32(v0 + sum)), u32((v0 >>> 5) + k3))
      v1 = u32(v1 - rhs1)
      rhs0 = bxor(bxor(u32(u32(v1 <<< 4) + k0), u32(v1 + sum)), u32((v1 >>> 5) + k1))
      v0 = u32(v0 - rhs0)
      {v0, v1, u32(sum - @tea_delta)}
    end)

    encode_u32_pair(v0, v1, endian)
  end

  @doc false
  def tea_decrypt_ecb(bin, key16, endian) do
    n = div(byte_size(bin), 8)
    for i <- 0..(n - 1) do
      tea_decrypt_block(binary_part(bin, i * 8, 8), key16, endian)
    end
    |> IO.iodata_to_binary()
  end

  # --- XTEA decryption (improved key schedule) ---

  defp xtea_decrypt_block(block8, key16, endian) when byte_size(block8) == 8 and byte_size(key16) == 16 do
    {v0, v1} = parse_u32_pair(block8, endian)
    keys = parse_u32_list(key16, endian)
    sum = u32(@tea_delta * 32)

    {v0, v1, _} = Enum.reduce(1..32, {v0, v1, sum}, fn _, {v0, v1, sum} ->
      mix1 = bxor(u32(v0 <<< 4), v0 >>> 5)
      rhs1 = bxor(u32(mix1 + v0), u32(sum + Enum.at(keys, (sum >>> 11) &&& 3)))
      v1 = u32(v1 - rhs1)
      sum = u32(sum - @tea_delta)
      mix0 = bxor(u32(v1 <<< 4), v1 >>> 5)
      rhs0 = bxor(u32(mix0 + v1), u32(sum + Enum.at(keys, sum &&& 3)))
      v0 = u32(v0 - rhs0)
      {v0, v1, sum}
    end)

    encode_u32_pair(v0, v1, endian)
  end

  @doc false
  def xtea_decrypt_ecb(bin, key16, endian) do
    n = div(byte_size(bin), 8)
    for i <- 0..(n - 1) do
      xtea_decrypt_block(binary_part(bin, i * 8, 8), key16, endian)
    end
    |> IO.iodata_to_binary()
  end

  # --- SPECK 64/128 (8-byte blocks, 128-bit key, 27 rounds, ARX) ---

  defp speck_64_128_expand_key(key_words) when length(key_words) == 4 do
    [k0, l0, l1, l2] = key_words
    {_l, k} = Enum.reduce(0..25, {%{0 => l0, 1 => l1, 2 => l2}, %{0 => k0}}, fn i, {l, k} ->
      li = Map.fetch!(l, i)
      ki = Map.fetch!(k, i)
      new_l = u32(bxor(u32(ki + ror32(li, 8)), i))
      new_k = u32(bxor(rol32(ki, 3), new_l))
      {Map.put(l, i + 3, new_l), Map.put(k, i + 1, new_k)}
    end)
    for i <- 0..26, do: Map.fetch!(k, i)
  end

  defp speck_64_128_decrypt_block(block8, key16, endian, rev_key) when byte_size(block8) == 8 and byte_size(key16) == 16 do
    {x, y} = parse_u32_pair(block8, endian)
    words = parse_u32_list(key16, endian)
    words = if rev_key, do: Enum.reverse(words), else: words
    rks = speck_64_128_expand_key(words)

    {x, y} = Enum.reduce(26..0//-1, {x, y}, fn i, {x, y} ->
      ki = Enum.at(rks, i)
      y = ror32(bxor(y, x), 3)
      x = rol32(u32(bxor(x, ki) - y), 8)
      {x, y}
    end)

    encode_u32_pair(x, y, endian)
  end

  # --- SPECK 128/128 (16-byte blocks, 128-bit key, 32 rounds) ---

  defp speck_128_128_expand_key(key_words) when length(key_words) == 2 do
    [k0, l0] = key_words
    {_l, k} = Enum.reduce(0..30, {%{0 => l0}, %{0 => k0}}, fn i, {l, k} ->
      li = Map.fetch!(l, i)
      ki = Map.fetch!(k, i)
      new_l = u64(bxor(u64(ki + ror64(li, 8)), i))
      new_k = u64(bxor(rol64(ki, 3), new_l))
      {Map.put(l, i + 1, new_l), Map.put(k, i + 1, new_k)}
    end)
    for i <- 0..31, do: Map.fetch!(k, i)
  end

  defp speck_128_128_decrypt_block(block16, key16, endian, rev_key) when byte_size(block16) == 16 and byte_size(key16) == 16 do
    {x, y} = parse_u64_pair(block16, endian)
    {w0, w1} = parse_u64_pair(key16, endian)
    words = if rev_key, do: [w1, w0], else: [w0, w1]
    rks = speck_128_128_expand_key(words)

    {x, y} = Enum.reduce(31..0//-1, {x, y}, fn i, {x, y} ->
      ki = Enum.at(rks, i)
      y = ror64(bxor(y, x), 3)
      x = rol64(u64(bxor(x, ki) - y), 8)
      {x, y}
    end)

    encode_u64_pair(x, y, endian)
  end

  # --- SIMON 64/128 (8-byte blocks, 128-bit key, 44 Feistel rounds) ---

  @z3_simon 0x1cc2dbf0c81a0e14

  defp simon_f(x), do: bxor(rol32(x, 1) &&& rol32(x, 8), rol32(x, 2))

  defp simon_64_128_expand_key(key_words) when length(key_words) == 4 do
    initial = key_words |> Enum.with_index() |> Map.new(fn {v, i} -> {i, v} end)

    keys = Enum.reduce(4..43, initial, fn i, keys ->
      tmp = ror32(Map.fetch!(keys, i - 1), 3)
      tmp = bxor(tmp, Map.fetch!(keys, i - 3))
      tmp = bxor(tmp, ror32(tmp, 1))
      z_bit = (@z3_simon >>> rem(i - 4, 62)) &&& 1
      ki = u32(bxor(bxor(bxor(not32(Map.fetch!(keys, i - 4)), tmp), z_bit), 3))
      Map.put(keys, i, ki)
    end)

    for i <- 0..43, do: Map.fetch!(keys, i)
  end

  defp simon_64_128_decrypt_block(block8, key16, endian, rev_key) when byte_size(block8) == 8 and byte_size(key16) == 16 do
    {x, y} = parse_u32_pair(block8, endian)
    words = parse_u32_list(key16, endian)
    words = if rev_key, do: Enum.reverse(words), else: words
    rks = simon_64_128_expand_key(words)

    {x, y} = Enum.reduce(43..0//-1, {x, y}, fn i, {x, y} ->
      ki = Enum.at(rks, i)
      {y, bxor(bxor(x, simon_f(y)), ki)}
    end)

    encode_u32_pair(x, y, endian)
  end

  # --- Candidate keys (128-bit / 16 bytes) ---

  defp candidate_keys do
    strings = [
      "LEGO", "EM", "SmartTag", "DA000001", "P11_audiobrick",
      "LtcaxE", "ExactL", "LEGOSmartPlay", "SmartBrick",
      "audiobrick", "EM9305", "DNP6G", "SmartPlay",
      "P11_audio", "LEGO Smart", "LEGOSmart", "005f",
      "kcirboidua_11P", "EMmicroelec", "ICODE", "SL2S",
      "20043-014", "DNP6G-010", "1055X", "810300"
    ]

    padded = Enum.map(strings, &pad16/1)

    numeric = [
      :binary.copy(<<0>>, 16),
      :binary.copy(<<1>>, 16),
      :binary.copy(<<0xFF>>, 16),
      <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
      <<0xA7, 0xE2, 0x4E, 0xD1, 0x0B, 0xBD, 0xA1, 0x13, 0, 0, 0, 0, 0, 0, 0, 0>>,
      <<0xD1, 0x4E, 0xE2, 0xA7, 0x13, 0xA1, 0xBD, 0x0B, 0, 0, 0, 0, 0, 0, 0, 0>>,
      :binary.copy(<<0x9E, 0x37, 0x79, 0xB9>>, 4),
    ]

    hash_derived = Enum.map(strings, fn s ->
      <<key::binary-16, _::binary>> = :crypto.hash(:sha256, s)
      key
    end)

    (padded ++ numeric ++ hash_derived) |> Enum.uniq()
  end

  # --- IV strategies for AES non-ECB modes ---

  defp iv_strategies do
    [
      {"zeros", fn _tag -> :binary.copy(<<0>>, 16) end},
      {"ones", fn _tag -> :binary.copy(<<1>>, 16) end},
      {"010C_repeat", fn _tag -> :binary.copy(<<1, 0x0C>>, 8) end},
      {"block0_pad", fn tag ->
        hex = Enum.at(tag["blocks"], 0) || "00000000"
        pad16(Base.decode16!(String.pad_trailing(String.upcase(hex), 8, "0"), case: :mixed))
      end},
      {"header5_pad", fn tag ->
        b0 = Enum.at(tag["blocks"], 0) || "00000000"
        bin = Base.decode16!(String.pad_trailing(String.upcase(b0), 8, "0"), case: :mixed)
        pad16(bin <> <<0x01>>)
      end},
      {"payload_len_repeat", fn tag ->
        b0 = Enum.at(tag["blocks"], 0) || "00000000"
        bin = Base.decode16!(String.pad_trailing(String.upcase(b0), 8, "0"), case: :mixed)
        :binary.copy(binary_part(bin, 0, 2), 8)
      end},
    ]
  end

  # --- Entropy analysis ---

  defp entropy_analysis(tag) do
    enc = encrypted_binary(tag)
    len = byte_size(enc)
    if len < 8 do
      IO.puts("  #{tag_label(tag)}: skip (encrypted < 8 bytes)")
    else
      bytes = :binary.bin_to_list(enc)
      overall = shannon_entropy(bytes)

      blocks_8 = for i <- 0..(div(len, 8) - 1), do: binary_part(enc, i * 8, 8)
      blocks_16 = for i <- 0..(div(len, 16) - 1), do: binary_part(enc, i * 16, 16)

      dup_8 = length(blocks_8) - length(Enum.uniq(blocks_8))
      dup_16 = length(blocks_16) - length(Enum.uniq(blocks_16))

      rem_8 = rem(len, 8)
      rem_16 = rem(len, 16)

      IO.puts("  #{tag_label(tag)}: #{len} enc bytes, entropy=#{Float.round(overall, 3)} bits/byte")
      IO.puts("    8B blocks: #{length(blocks_8)} complete (#{rem_8} remainder) | #{dup_8} duplicates")
      IO.puts("    16B blocks: #{length(blocks_16)} complete (#{rem_16} remainder) | #{dup_16} duplicates")
      if dup_8 > 0, do: IO.puts("    WARNING: repeated 8-byte blocks (possible ECB mode)")
      if dup_16 > 0, do: IO.puts("    WARNING: repeated 16-byte blocks (possible ECB mode)")
    end
  end

  defp shannon_entropy(bytes) when length(bytes) < 2, do: 0.0
  defp shannon_entropy(bytes) do
    n = length(bytes)
    Enum.frequencies(bytes)
    |> Enum.reduce(0.0, fn {_, count}, acc ->
      p = count / n
      acc - p * :math.log2(p)
    end)
  end

  # --- Relaxed validation (heuristic scoring without requiring magic match) ---

  defp relaxed_score(dec_bytes, enc_len) when is_list(dec_bytes) and length(dec_bytes) >= 8 do
    entropy = shannon_entropy(dec_bytes)
    entropy_pts = max(0, (8.0 - entropy) * 12)

    printable = Enum.count(dec_bytes, fn b -> (b >= 0x20 and b <= 0x7E) or b == 0 end)
    ascii_pts = printable / length(dec_bytes) * 40

    trailing = dec_bytes |> Enum.reverse() |> Enum.take_while(&(&1 == 0)) |> length()
    pad_pts = min(trailing * 3, 20)

    type_hi = Enum.at(dec_bytes, 1)
    len_lo = Enum.at(dec_bytes, 2)
    len_hi = Enum.at(dec_bytes, 3)
    content_len = len_lo + bsl(len_hi, 8)
    tlv_pts = if (type_hi &&& 0xC0) == 0 and content_len > 0 and content_len <= enc_len, do: 15, else: 0

    magic = Enum.slice(dec_bytes, 4, 4) |> IO.iodata_to_binary()
    magic_pts = if magic in @all_event_magics, do: 50, else: 0

    crc_pts = check_crc32_presence(dec_bytes)

    tlv_chain_pts = tlv_chain_score(dec_bytes, enc_len)

    total = entropy_pts + ascii_pts + pad_pts + tlv_pts + magic_pts + crc_pts + tlv_chain_pts
    {total, %{ent: Float.round(entropy, 2), ascii: Float.round(ascii_pts, 1), pad: pad_pts,
              tlv: tlv_pts, magic: magic_pts, crc: crc_pts, tlv_chain: tlv_chain_pts}}
  end

  defp relaxed_score(_dec_bytes, _enc_len), do: {0.0, %{}}

  # Score if first TLV content_len implies next TLV starts in-bounds and looks plausible
  defp tlv_chain_score(dec_bytes, enc_len) when length(dec_bytes) >= 8 do
    len_lo = Enum.at(dec_bytes, 2)
    len_hi = Enum.at(dec_bytes, 3)
    content_len = len_lo + bsl(len_hi, 8)
    next_start = 8 + content_len
    if next_start + 8 <= length(dec_bytes) do
      next_hi = Enum.at(dec_bytes, next_start + 1)
      next_len_lo = Enum.at(dec_bytes, next_start + 2)
      next_len_hi = Enum.at(dec_bytes, next_start + 3)
      next_len = next_len_lo + bsl(next_len_hi, 8)
      type_ok = (next_hi &&& 0xC0) == 0
      len_ok = next_len >= 0 and next_len <= enc_len
      if type_ok and len_ok, do: 20, else: 0
    else
      0
    end
  end

  defp tlv_chain_score(_, _), do: 0

  defp check_crc32_presence(dec_bytes) when length(dec_bytes) >= 8 do
    bin = IO.iodata_to_binary(dec_bytes)
    len = byte_size(bin)
    cond do
      len >= 8 ->
        head = binary_part(bin, 0, len - 4)
        tail_crc = binary_part(bin, len - 4, 4)
        expected = <<:erlang.crc32(head)::32-little>>
        if tail_crc == expected, do: 30, else: 0
      true -> 0
    end
  end

  defp check_crc32_presence(_), do: 0

  # --- Known-plaintext magic recovery (stream cipher test) ---

  defp try_known_plaintext_magic(unique_tags) do
    IO.puts("  If encryption is a stream cipher with a fixed keystream, all tags of the")
    IO.puts("  same category should produce identical recovered keystream at offsets 4-7.\n")

    results =
      Enum.map(unique_tags, fn tag ->
        enc = encrypted_binary(tag)
        magic = expected_event_magic(tag)
        cat = tag_category(tag)

        if byte_size(enc) < 8 or is_nil(magic) do
          IO.puts("    #{tag_label(tag)}: skip (< 8 bytes or unknown category)")
          nil
        else
          enc_at_4 = binary_part(enc, 4, 4) |> :binary.bin_to_list()
          mag_list = :binary.bin_to_list(magic)
          ks = Enum.zip(enc_at_4, mag_list) |> Enum.map(fn {e, p} -> bxor(e, p) end)
          ks_hex = Enum.map(ks, fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
          IO.puts("    #{tag_label(tag)} [#{cat}]: K[4:7] = #{ks_hex}")
          {cat, ks}
        end
      end)
      |> Enum.reject(&is_nil/1)

    for cat <- [:identity, :item] do
      ks_values = results |> Enum.filter(fn {c, _} -> c == cat end) |> Enum.map(&elem(&1, 1))
      unique_ks = Enum.uniq(ks_values)
      IO.puts("  #{cat} tags: #{length(ks_values)} total, #{length(unique_ks)} unique K[4:7]")
      if length(unique_ks) == 1 and length(ks_values) > 1 do
        IO.puts("  >>> ALL #{cat} tags share K[4:7] — consistent with fixed-keystream stream cipher!")
      end
    end

    all_ks = Enum.map(results, &elem(&1, 1)) |> Enum.uniq()
    if length(all_ks) > 1 do
      IO.puts("  K[4:7] differs across tags — NOT a simple fixed-keystream cipher")
      IO.puts("  (could be content-dependent IV/nonce, block cipher, or per-tag key derivation)")
    end
    IO.puts("")
  end

  # --- MAC length inference: enc_len - 4/8/16 = plaintext_len ---
  defp mac_length_inference(unique_tags) do
    by_cat = Enum.group_by(unique_tags, &tag_category/1)
    for {cat, tags} <- by_cat do
      IO.puts("  --- #{cat} (#{length(tags)} tags) ---")
      for tag <- tags do
        enc = encrypted_binary(tag)
        enc_len = byte_size(enc)
        pt_4 = enc_len - 4
        pt_8 = enc_len - 8
        pt_16 = enc_len - 16
        IO.puts("    #{tag_label(tag)}: enc=#{enc_len}  plaintext_len if MAC=4/8/16: #{pt_4} / #{pt_8} / #{pt_16}")
      end
      enc_lens = Enum.map(tags, fn t -> byte_size(encrypted_binary(t)) end) |> Enum.uniq() |> Enum.sort()
      IO.puts("    enc_len values: #{Enum.join(enc_lens, ", ")}")
    end
    IO.puts("")
  end

  # --- Keystream at bytes 8-15: if first TLV content is short, bytes 8+ may be zero padding ---
  defp try_keystream_extended(unique_tags) do
    by_cat = Enum.group_by(unique_tags, &tag_category/1)
    for {cat, tags} <- by_cat, length(tags) >= 1 do
      enc_list = Enum.map(tags, fn t -> encrypted_binary(t) end)
      min_len = enc_list |> Enum.map(&byte_size/1) |> Enum.min()
      if min_len >= 16 do
        bytes_8_15 = Enum.map(enc_list, fn enc -> binary_part(enc, 8, 8) end)
        uniq = Enum.uniq(bytes_8_15)
        IO.puts("  #{cat}: #{length(tags)} tags, bytes 8-15: #{length(uniq)} unique")
        if length(uniq) == 1 and length(tags) > 1 do
          IO.puts("    >>> All #{cat} tags identical at 8-15 — consistent with same plaintext/keystream")
        end
      end
    end
    IO.puts("")
  end

  # --- Constrain P[0:3]: enumerate type_id (0x0000..0x0FFF) and content_len, compute K[0:3] = C[0:3] ⊕ P ---
  defp try_constrain_p0_p3(unique_tags) do
    by_cat = Enum.group_by(unique_tags, &tag_category/1)
    for {cat, tags} <- by_cat, length(tags) >= 1 do
      enc_list = Enum.map(tags, fn t -> encrypted_binary(t) end)
      if Enum.all?(enc_list, fn enc -> byte_size(enc) >= 4 end) do
        # For each (type_id, content_len) try content_len in [enc_len-8, enc_len-12, ...] plausible range
        first_enc = List.first(enc_list)
        enc_len = byte_size(first_enc)
        content_len_opts = [enc_len - 8, enc_len - 12, enc_len - 16, max(0, enc_len - 20)] |> Enum.uniq() |> Enum.filter(&(&1 >= 0))
        hits = for type_id <- 0..0x0FFF,
                  content_len <- content_len_opts,
                  content_len <= 300 do
          pt = <<type_id::16-little, content_len::16-little>>
          # K[0:3] = C[0:3] ⊕ P[0:3] for first tag
          c0 = binary_part(first_enc, 0, 4) |> :binary.bin_to_list()
          p0 = :binary.bin_to_list(pt)
          k0 = Enum.zip(c0, p0) |> Enum.map(fn {a, b} -> bxor(a, b) end)
          # Check if same K[0:3] decrypts other tags to plausible TLV (type_ok, len_ok at 0-3)
          all_ok = Enum.all?(enc_list, fn enc ->
            if byte_size(enc) < 4, do: false, else: true
          end)
          {type_id, content_len, k0, all_ok}
        end
        best = Enum.take(hits, 5)
        IO.puts("  #{cat}: sampled type_id/content_len → K[0:3] (first 5)")
        for {tid, clen, k0, _} <- best do
          k_hex = k0 |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
          IO.puts("    type_id=0x#{Integer.to_string(tid, 16)} content_len=#{clen}  K[0:3]=#{k_hex}")
        end
      end
    end
    IO.puts("")
  end

  # --- TEA/XTEA cross-tag runner ---

  defp try_tea_xtea_all(unique_tags) do
    keys = candidate_keys()
    combos = length(keys) * 4
    IO.puts("  Testing #{length(keys)} keys × 2 algos × 2 endiannesses = #{combos} combos\n")

    hits =
      for algo <- [:tea, :xtea],
          endian <- [:little, :big],
          key <- keys,
          reduce: [] do
        hits ->
          results =
            Enum.map(unique_tags, fn tag ->
              enc = encrypted_binary(tag)
              if byte_size(enc) < 8 do
                {:fail, %{}}
              else
                block = binary_part(enc, 0, 8)
                dec = case algo do
                  :tea -> tea_decrypt_block(block, key, endian)
                  :xtea -> xtea_decrypt_block(block, key, endian)
                end
                validate_tlv_magic(:binary.bin_to_list(dec), tag)
              end
            end)

          pass = Enum.count(results, &(elem(&1, 0) == :pass))
          if pass >= 1 do
            key_hex = Base.encode16(key, case: :lower)
            key_str = key |> trim_null() |> inspect()
            IO.puts("  HIT #{algo}/#{endian}: #{pass}/#{length(unique_tags)} pass | key=#{key_str} (#{key_hex})")
            detail = Enum.zip(unique_tags, results) |> Enum.map(fn {t, {s, d}} ->
              "      #{tag_label(t)}: #{s} #{inspect(d)}"
            end) |> Enum.join("\n")
            IO.puts(detail)
            [{algo, endian, key, pass} | hits]
          else
            hits
          end
      end

    if hits == [] do
      IO.puts("  No TEA/XTEA key passed validation on any tag")
    else
      IO.puts("\n  #{length(hits)} candidate(s) found")
    end
    IO.puts("")
  end

  # --- AES non-ECB modes cross-tag runner ---

  defp try_aes_modes_all(unique_tags) do
    keys = candidate_keys()
    modes = [:aes_128_cbc, :aes_128_ctr, :aes_128_cfb128, :aes_128_ofb]
    iv_strats = iv_strategies()
    combos = length(keys) * length(modes) * length(iv_strats)
    IO.puts("  Testing #{length(keys)} keys × #{length(modes)} modes × #{length(iv_strats)} IVs = #{combos} combos\n")

    hits =
      for mode <- modes,
          key <- keys,
          {iv_name, iv_fn} <- iv_strats,
          reduce: [] do
        hits ->
          results =
            Enum.map(unique_tags, fn tag ->
              enc = encrypted_binary(tag)
              iv = iv_fn.(tag)
              min_len = if mode == :aes_128_cbc, do: 16, else: 8
              if byte_size(enc) < min_len do
                {:fail, %{}}
              else
                data = if mode == :aes_128_cbc do
                  n = div(byte_size(enc), 16) * 16
                  if n > 0, do: binary_part(enc, 0, n), else: enc
                else
                  enc
                end
                try do
                  dec = :crypto.crypto_one_time(mode, key, iv, data, false)
                  validate_tlv_magic(:binary.bin_to_list(dec) |> Enum.take(8), tag)
                rescue
                  _ -> {:fail, %{error: true}}
                end
              end
            end)

          pass = Enum.count(results, &(elem(&1, 0) == :pass))
          if pass >= 1 do
            mode_str = mode |> Atom.to_string() |> String.replace("aes_128_", "AES-")
            key_str = key |> trim_null() |> inspect()
            IO.puts("  HIT #{mode_str}/iv=#{iv_name}: #{pass}/#{length(unique_tags)} pass | key=#{key_str}")
            detail = Enum.zip(unique_tags, results) |> Enum.map(fn {t, {s, d}} ->
              "      #{tag_label(t)}: #{s} #{inspect(d)}"
            end) |> Enum.join("\n")
            IO.puts(detail)
            [{mode, iv_name, key, pass} | hits]
          else
            hits
          end
      end

    if hits == [] do
      IO.puts("  No AES key/mode/IV passed validation on any tag")
    else
      IO.puts("\n  #{length(hits)} candidate(s) found")
    end
    IO.puts("")
  end

  # --- SPECK / SIMON cross-tag runner ---

  defp try_speck_simon_all(unique_tags) do
    keys = candidate_keys()
    algos = [:speck_64_128, :speck_128_128, :simon_64_128]
    combos = length(keys) * length(algos) * 2 * 2
    IO.puts("  Testing #{length(keys)} keys × #{length(algos)} algos × 2 endian × 2 key-orders = #{combos} combos\n")

    hits =
      for algo <- algos,
          endian <- [:little, :big],
          rev_key <- [false, true],
          key <- keys,
          reduce: [] do
        hits ->
          block_size = if algo == :speck_128_128, do: 16, else: 8

          results =
            Enum.map(unique_tags, fn tag ->
              enc = encrypted_binary(tag)
              if byte_size(enc) < block_size do
                {:fail, %{}}
              else
                block = binary_part(enc, 0, block_size)
                dec = try do
                  case algo do
                    :speck_64_128 -> speck_64_128_decrypt_block(block, key, endian, rev_key)
                    :speck_128_128 -> speck_128_128_decrypt_block(block, key, endian, rev_key)
                    :simon_64_128 -> simon_64_128_decrypt_block(block, key, endian, rev_key)
                  end
                rescue
                  _ -> nil
                end
                if dec, do: validate_tlv_magic(:binary.bin_to_list(dec), tag), else: {:fail, %{}}
              end
            end)

          pass = Enum.count(results, &(elem(&1, 0) == :pass))
          if pass >= 1 do
            key_str = key |> trim_null() |> inspect()
            rev_str = if rev_key, do: "/rev", else: ""
            IO.puts("  HIT #{algo}/#{endian}#{rev_str}: #{pass}/#{length(unique_tags)} pass | key=#{key_str}")
            detail = Enum.zip(unique_tags, results) |> Enum.map(fn {t, {s, d}} ->
              "      #{tag_label(t)}: #{s} #{inspect(d)}"
            end) |> Enum.join("\n")
            IO.puts(detail)
            [{algo, endian, rev_key, key, pass} | hits]
          else
            hits
          end
      end

    if hits == [] do
      IO.puts("  No SPECK/SIMON key passed validation on any tag")
    else
      IO.puts("\n  #{length(hits)} candidate(s) found")
    end
    IO.puts("")
  end

  # --- Relaxed scoring scan (all ciphers, heuristic validation) ---

  defp try_relaxed_scan(unique_tags) do
    IO.puts("  Scoring ALL cipher × key combos on first tag by entropy, structure, CRC, magic\n")
    keys = candidate_keys()
    first_tag = List.first(unique_tags)
    enc = encrypted_binary(first_tag)
    enc_len = byte_size(enc)

    if enc_len < 16 do
      IO.puts("  Skip: first tag < 16 encrypted bytes\n")
    else
      block8 = binary_part(enc, 0, 8)
      block16 = binary_part(enc, 0, 16)

      attempts =
        for {algo, block, extra_variants} <- [
              {:tea, block8, [{:little, false}, {:big, false}]},
              {:xtea, block8, [{:little, false}, {:big, false}]},
              {:speck_64_128, block8, [{:little, false}, {:big, false}, {:little, true}, {:big, true}]},
              {:simon_64_128, block8, [{:little, false}, {:big, false}, {:little, true}, {:big, true}]},
              {:speck_128_128, block16, [{:little, false}, {:big, false}, {:little, true}, {:big, true}]},
              {:aes_ecb, block16, [{:na, false}]},
            ],
            {endian, rev} <- extra_variants,
            key <- keys,
            reduce: [] do
          acc ->
            dec = try do
              case algo do
                :tea -> tea_decrypt_block(block, key, endian)
                :xtea -> xtea_decrypt_block(block, key, endian)
                :speck_64_128 -> speck_64_128_decrypt_block(block, key, endian, rev)
                :simon_64_128 -> simon_64_128_decrypt_block(block, key, endian, rev)
                :speck_128_128 -> speck_128_128_decrypt_block(block, key, endian, rev)
                :aes_ecb -> :crypto.crypto_one_time(:aes_128_ecb, key, block, false)
              end
            rescue
              _ -> nil
            end
            if dec do
              bytes = :binary.bin_to_list(dec)
              {score, detail} = relaxed_score(bytes, enc_len)
              [{algo, endian, rev, key, score, detail, bytes} | acc]
            else
              acc
            end
        end

      top = attempts |> Enum.sort_by(fn {_, _, _, _, s, _, _} -> -s end) |> Enum.take(15)

      IO.puts("  Top 15 decryption attempts (#{tag_label(first_tag)}, first block):")
      for {algo, endian, rev, key, score, detail, dec} <- top do
        key_str = key |> trim_null() |> inspect()
        rev_s = if rev, do: "/rev", else: ""
        hex = dec |> Enum.take(8) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
        IO.puts("    #{Float.round(score, 1)} pts | #{algo}/#{endian}#{rev_s} key=#{key_str}")
        IO.puts("           dec=#{hex}  #{inspect(detail)}")
      end
      IO.puts("")
    end
  end

  # --- Differential analysis (pairwise XOR, per-position distribution) ---

  defp differential_analysis(unique_tags) do
    tag_data = Enum.map(unique_tags, fn tag ->
      {tag_label(tag), tag_category(tag), encrypted_binary(tag)}
    end)

    for cat <- [:identity, :item] do
      cat_tags = Enum.filter(tag_data, fn {_, c, _} -> c == cat end)
      if length(cat_tags) >= 2 do
        IO.puts("  --- #{cat} tags (#{length(cat_tags)}) ---")
        pairs = for {a, _, da} <- cat_tags, {b, _, db} <- cat_tags, a < b, do: {a, b, da, db}

        for {na, nb, da, db} <- pairs do
          min_len = min(byte_size(da), byte_size(db))
          xor = for i <- 0..(min_len - 1), do: bxor(:binary.at(da, i), :binary.at(db, i))
          zeros = Enum.count(xor, &(&1 == 0))
          hw = xor |> Enum.map(&popcount/1) |> then(fn l -> Enum.sum(l) / length(l) end)
          hex16 = xor |> Enum.take(16) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
          IO.puts("    #{na} vs #{nb}")
          IO.puts("      #{min_len} bytes, #{zeros} identical, avg hamming=#{Float.round(hw, 2)}")
          IO.puts("      XOR[0:15]: #{hex16}")
          if zeros > 0 do
            zpos = xor |> Enum.with_index() |> Enum.filter(fn {b, _} -> b == 0 end) |> Enum.map(&elem(&1, 1))
            IO.puts("      zero at: #{Enum.take(zpos, 20) |> Enum.join(", ")}")
          end
        end
        IO.puts("")
      end
    end

    IO.puts("  --- Cross-category XOR (identity[0] vs item[0]) ---")
    id_tags = Enum.filter(tag_data, fn {_, c, _} -> c == :identity end)
    it_tags = Enum.filter(tag_data, fn {_, c, _} -> c == :item end)
    if length(id_tags) >= 1 and length(it_tags) >= 1 do
      {_, _, d1} = List.first(id_tags)
      {_, _, d2} = List.first(it_tags)
      min_len = min(byte_size(d1), byte_size(d2))
      xor = for i <- 0..(min_len - 1), do: bxor(:binary.at(d1, i), :binary.at(d2, i))
      magic_xor = :binary.bin_to_list(bxor_bin(@identity_event_magic, @item_event_magic))
      bytes_4_7 = Enum.slice(xor, 4, 4)
      magic_match = bytes_4_7 == magic_xor
      hex16 = xor |> Enum.take(16) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
      IO.puts("    XOR[0:15]: #{hex16}")
      IO.puts("    XOR[4:7] matches magic_xor? #{magic_match}")
      if magic_match do
        IO.puts("    >>> ECB-like: same keystream/block transform at offsets 4-7!")
      end
    end

    IO.puts("\n  --- Per-position byte distribution (first 16 encrypted bytes) ---")
    min_common = tag_data |> Enum.map(fn {_, _, d} -> byte_size(d) end) |> Enum.min()
    for pos <- 0..min(15, min_common - 1) do
      vals = Enum.map(tag_data, fn {_, _, d} -> :binary.at(d, pos) end)
      uniq = Enum.uniq(vals)
      hex_v = uniq |> Enum.take(10) |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(",")
      IO.puts("    enc[#{String.pad_leading(Integer.to_string(pos), 2)}]: #{length(uniq)}/#{length(vals)} unique (#{hex_v})")
    end

    IO.puts("\n  --- Block-boundary XOR pattern (8B / 16B alignment) ---")
    {_, _, first_enc} = List.first(tag_data)
    if byte_size(first_enc) >= 32 do
      for {bsize, label} <- [{8, "8B"}, {16, "16B"}] do
        n_blocks = div(byte_size(first_enc), bsize)
        if n_blocks >= 2 do
          b0 = binary_part(first_enc, 0, bsize) |> :binary.bin_to_list()
          b1 = binary_part(first_enc, bsize, bsize) |> :binary.bin_to_list()
          xor = Enum.zip(b0, b1) |> Enum.map(fn {a, b} -> bxor(a, b) end)
          hex = xor |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join(" ")
          zeros = Enum.count(xor, &(&1 == 0))
          IO.puts("    #{label} block0 XOR block1: #{hex} (#{zeros} zeros)")
        end
      end
    end
    IO.puts("")
  end

  defp popcount(0), do: 0
  defp popcount(n) when n > 0, do: (n &&& 1) + popcount(n >>> 1)

  defp bxor_bin(a, b) when byte_size(a) == byte_size(b) do
    al = :binary.bin_to_list(a)
    bl = :binary.bin_to_list(b)
    Enum.zip(al, bl) |> Enum.map(fn {x, y} -> bxor(x, y) end) |> IO.iodata_to_binary()
  end

  # ---------------------------------------------------------------------------
  # Compression / alternative-encoding hypothesis
  # ---------------------------------------------------------------------------

  defp compression_analysis(unique_tags) do
    IO.puts("  Testing whether the 'encrypted' region is actually compressed or encoded\n")

    tag_data =
      Enum.map(unique_tags, fn tag ->
        {tag_label(tag), encrypted_binary(tag), full_tag_binary(tag)}
      end)

    IO.puts("  --- 1. Standard decompression attempts (zlib, gzip, raw deflate) ---")
    for {label, enc, full} <- tag_data do
      IO.puts("  #{label} (#{byte_size(enc)} enc bytes):")
      slices = [
        {"enc_full", enc},
        {"enc_skip1", safe_slice(enc, 1)},
        {"enc_skip2", safe_slice(enc, 2)},
        {"enc_skip4", safe_slice(enc, 4)},
        {"full_payload", full}
      ]
      for {sname, data} <- slices, byte_size(data) > 2 do
        try_all_decompress(data, sname)
      end
      IO.puts("")
    end

    IO.puts("  --- 2. Byte-frequency analysis (compression vs encryption) ---")
    for {label, enc, _} <- tag_data do
      byte_frequency_report(label, enc)
    end

    IO.puts("\n  --- 3. Transforms + decompression (obfuscation check) ---")
    {first_label, first_enc, _} = List.first(tag_data)
    input_len = byte_size(first_enc)
    IO.puts("  Testing transforms on #{first_label} (#{input_len} bytes):")
    IO.puts("  (only counting decompression where output >= 50% of input size)")
    transforms = [
      {"bit_reverse", &bit_reverse_bytes/1},
      {"nibble_swap", &nibble_swap_bytes/1},
      {"byte_reverse", &byte_reverse/1},
      {"complement", &complement_bytes/1},
      {"rol1", &(rol_all_bytes(&1, 1))},
      {"rol2", &(rol_all_bytes(&1, 2))},
      {"rol3", &(rol_all_bytes(&1, 3))},
      {"rol4", &(rol_all_bytes(&1, 4))},
      {"xor_0xFF", &xor_const(&1, 0xFF)},
      {"xor_0xA5", &xor_const(&1, 0xA5)},
      {"xor_0x55", &xor_const(&1, 0x55)}
    ]
    min_output = div(input_len, 2)
    for {tname, tfn} <- transforms do
      transformed = tfn.(first_enc)
      {real_hits, spurious} = try_all_decompress_checked(transformed, min_output)
      cond do
        real_hits > 0 ->
          IO.puts("    #{tname}: #{real_hits} REAL decompression hit(s) (output >= #{min_output} bytes)!")
        spurious > 0 ->
          IO.puts("    #{tname}: #{spurious} spurious hit(s) (output < #{min_output} bytes, likely false positive)")
        true -> :ok
      end
    end
    IO.puts("    (no real hits = transforms did not reveal compression)")

    IO.puts("\n  --- 4. Structural interpretation (CBOR, raw TLV, LZ4 frame) ---")
    for {label, enc, _} <- tag_data do
      structural_probe(label, enc)
    end

    IO.puts("\n  --- 5. Autocorrelation (repeating-pattern detection) ---")
    for {label, enc, _} <- tag_data do
      autocorrelation_report(label, enc)
    end

    IO.puts("\n  --- 6. Runs test (randomness vs structure) ---")
    for {label, enc, _} <- tag_data do
      runs_test_report(label, enc)
    end

    IO.puts("\n  --- 7. Digram / trigram frequency (top-N most common) ---")
    for {label, enc, _} <- tag_data do
      ngram_report(label, enc)
    end

    IO.puts("\n  --- SYNTHESIS: Compression vs Encryption ---")
    all_ics = Enum.map(tag_data, fn {_, enc, _} -> index_of_coincidence(:binary.bin_to_list(enc)) end)
    avg_ic = Enum.sum(all_ics) / length(all_ics)
    all_unique_digrams = Enum.all?(tag_data, fn {_, enc, _} ->
      bytes = :binary.bin_to_list(enc)
      grams = bytes |> Enum.chunk_every(2, 1, :discard) |> Enum.frequencies()
      Enum.all?(grams, fn {_, c} -> c == 1 end)
    end)
    IO.puts("  Average IC across all tags: #{Float.round(avg_ic, 6)}")
    IO.puts("  Random IC expected:         0.003906")
    IO.puts("  English text IC:            ~0.065")
    IO.puts("  Compressed data IC:         typically 0.004-0.008 (slightly above random)")
    IO.puts("  All digrams unique:         #{all_unique_digrams}")
    IO.puts("")
    cond do
      avg_ic > 0.008 ->
        IO.puts("  VERDICT: IC significantly elevated — data may be compressed or structured")
      avg_ic > 0.005 ->
        IO.puts("  VERDICT: IC slightly elevated — inconclusive, could be weak compression")
      all_unique_digrams ->
        IO.puts("  VERDICT: Data is statistically indistinguishable from random.")
        IO.puts("  All digrams unique, IC matches random expectation, no standard")
        IO.puts("  decompressor works, runs test normal, autocorrelation zero.")
        IO.puts("  This strongly indicates ENCRYPTION, not compression.")
        IO.puts("  The ASIC performs decryption with a key burned into silicon.")
      true ->
        IO.puts("  VERDICT: Likely encrypted (IC near random, no compression signatures)")
    end
    IO.puts("")
  end

  defp full_tag_binary(tag) do
    blocks = tag["blocks"]
    last_idx = last_payload_block_index(blocks)
    payload_len = payload_length_from_header(blocks)
    all_data_blocks = blocks |> Enum.take(last_idx + 1)
    bin = blocks_to_binary(all_data_blocks)
    if payload_len && byte_size(bin) > payload_len do
      binary_part(bin, 0, payload_len)
    else
      bin
    end
  end

  defp safe_slice(bin, offset) when offset < byte_size(bin),
    do: binary_part(bin, offset, byte_size(bin) - offset)
  defp safe_slice(_bin, _offset), do: <<>>

  defp try_all_decompress(data, slice_name) do
    try_zlib(data, slice_name)
    try_gzip(data, slice_name)
    for wbits <- [15, 12, 10, 8] do
      try_raw_inflate(data, wbits, slice_name)
    end
  end

  defp try_all_decompress_checked(data, min_output_size) do
    results =
      [try_zlib_silent(data), try_gzip_silent(data)] ++
      Enum.map([15, 12, 10, 8], &try_raw_inflate_silent(data, &1))
    real = Enum.count(results, fn
      {:ok, r} -> byte_size(r) >= min_output_size
      _ -> false
    end)
    spurious = Enum.count(results, fn
      {:ok, r} -> byte_size(r) < min_output_size
      _ -> false
    end)
    {real, spurious}
  end

  defp try_zlib(data, label) do
    case try_zlib_silent(data) do
      {:ok, result} ->
        IO.puts("    #{label} zlib: SUCCESS — #{byte_size(result)} bytes decompressed")
        hex_preview(result)
      _ -> :ok
    end
  end

  defp try_zlib_silent(data) do
    try do
      {:ok, :zlib.uncompress(data)}
    rescue
      _ -> :error
    end
  end

  defp try_gzip(data, label) do
    case try_gzip_silent(data) do
      {:ok, result} ->
        IO.puts("    #{label} gzip: SUCCESS — #{byte_size(result)} bytes decompressed")
        hex_preview(result)
      _ -> :ok
    end
  end

  defp try_gzip_silent(data) do
    try do
      {:ok, :zlib.gunzip(data)}
    rescue
      _ -> :error
    end
  end

  defp try_raw_inflate(data, wbits, label) do
    case try_raw_inflate_silent(data, wbits) do
      {:ok, result} ->
        IO.puts("    #{label} raw_deflate(w=#{wbits}): SUCCESS — #{byte_size(result)} bytes")
        hex_preview(result)
      _ -> :ok
    end
  end

  defp try_raw_inflate_silent(data, wbits) do
    try do
      z = :zlib.open()
      :zlib.inflateInit(z, -wbits)
      result = :zlib.inflate(z, data) |> IO.iodata_to_binary()
      :zlib.inflateEnd(z)
      :zlib.close(z)
      if byte_size(result) > 0, do: {:ok, result}, else: :error
    rescue
      _ -> :error
    end
  end

  defp hex_preview(bin) do
    n = min(32, byte_size(bin))
    hex =
      bin
      |> binary_part(0, n)
      |> :binary.bin_to_list()
      |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end)
      |> Enum.join(" ")
    ascii =
      bin
      |> binary_part(0, n)
      |> :binary.bin_to_list()
      |> Enum.map(fn b -> if b >= 0x20 and b <= 0x7E, do: <<b>>, else: "." end)
      |> Enum.join()
    IO.puts("      hex: #{hex}")
    IO.puts("      ascii: #{ascii}")
  end

  # -- Byte-frequency analysis --

  defp byte_frequency_report(label, enc) do
    bytes = :binary.bin_to_list(enc)
    n = length(bytes)
    freq = Enum.frequencies(bytes)
    n_unique = map_size(freq)
    expected_unique = round(256 * (1 - :math.pow(255 / 256, n)))
    max_count = freq |> Map.values() |> Enum.max(fn -> 0 end)
    top5 =
      freq
      |> Enum.sort_by(fn {_, c} -> -c end)
      |> Enum.take(5)
      |> Enum.map(fn {v, c} ->
        "0x#{Integer.to_string(v, 16) |> String.pad_leading(2, "0")}=#{c}"
      end)
      |> Enum.join(", ")

    chi_sq = chi_squared(bytes)

    mono_ic = index_of_coincidence(bytes)

    IO.puts("  #{label} (#{n} bytes):")
    IO.puts("    unique values: #{n_unique}/256 (expected ~#{expected_unique} for random)")
    IO.puts("    max frequency: #{max_count} (expected ~#{Float.round(n / 256, 1)} for random)")
    IO.puts("    top-5 bytes: #{top5}")
    IO.puts("    chi-squared (uniform): #{Float.round(chi_sq, 1)} (expected ~255 for random, df=255)")
    IO.puts("    index of coincidence: #{Float.round(mono_ic, 6)} (expected 0.003906 for random, ~0.065 English)")

    cond do
      mono_ic > 0.01 ->
        IO.puts("    >>> IC significantly above random — possible compressed/structured data")
      mono_ic > 0.006 ->
        IO.puts("    >>> IC slightly elevated — inconclusive")
      true ->
        IO.puts("    >>> IC consistent with random/encrypted data")
    end
  end

  defp chi_squared(bytes) do
    n = length(bytes)
    expected = n / 256
    freq = Enum.frequencies(bytes)
    Enum.reduce(0..255, 0.0, fn val, acc ->
      observed = Map.get(freq, val, 0)
      acc + (observed - expected) * (observed - expected) / max(expected, 0.001)
    end)
  end

  defp index_of_coincidence(bytes) do
    n = length(bytes)
    if n < 2 do
      0.0
    else
      freq = Enum.frequencies(bytes)
      sum = Enum.reduce(freq, 0, fn {_, c}, acc -> acc + c * (c - 1) end)
      sum / (n * (n - 1))
    end
  end

  # -- Simple byte transforms --

  defp bit_reverse_bytes(bin) do
    bin
    |> :binary.bin_to_list()
    |> Enum.map(&bit_reverse_byte/1)
    |> :binary.list_to_bin()
  end

  defp bit_reverse_byte(b) do
    Enum.reduce(0..7, 0, fn i, acc ->
      acc ||| ((b >>> i &&& 1) <<< (7 - i))
    end)
  end

  defp nibble_swap_bytes(bin) do
    bin
    |> :binary.bin_to_list()
    |> Enum.map(fn b -> (b >>> 4) ||| ((b &&& 0x0F) <<< 4) end)
    |> :binary.list_to_bin()
  end

  defp byte_reverse(bin), do: bin |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

  defp complement_bytes(bin) do
    bin |> :binary.bin_to_list() |> Enum.map(&bxor(&1, 0xFF)) |> :binary.list_to_bin()
  end

  defp rol_all_bytes(bin, n) do
    bin
    |> :binary.bin_to_list()
    |> Enum.map(fn b -> ((b <<< n) ||| (b >>> (8 - n))) &&& 0xFF end)
    |> :binary.list_to_bin()
  end

  defp xor_const(bin, c) do
    bin |> :binary.bin_to_list() |> Enum.map(&bxor(&1, c)) |> :binary.list_to_bin()
  end

  # -- Structural probes --

  defp structural_probe(label, enc) do
    bytes = :binary.bin_to_list(enc)
    n = byte_size(enc)
    IO.puts("  #{label} (#{n} bytes):")

    # LZ4 frame magic: 04 22 4D 18
    if n >= 4 do
      <<b0, b1, b2, b3, _::binary>> = enc
      if b0 == 0x04 and b1 == 0x22 and b2 == 0x4D and b3 == 0x18 do
        IO.puts("    >>> LZ4 frame magic detected!")
      end
    end

    # zstd magic: 28 B5 2F FD
    if n >= 4 do
      <<b0, b1, b2, b3, _::binary>> = enc
      if b0 == 0x28 and b1 == 0xB5 and b2 == 0x2F and b3 == 0xFD do
        IO.puts("    >>> Zstandard magic detected!")
      end
    end

    # bzip2: 42 5A 68 ("BZh")
    if n >= 3 do
      <<b0, b1, b2, _::binary>> = enc
      if b0 == 0x42 and b1 == 0x5A and b2 == 0x68 do
        IO.puts("    >>> bzip2 magic detected!")
      end
    end

    # LZMA: first byte 5D usually, properties byte
    if n >= 5 do
      <<props, _::binary>> = enc
      if props in [0x5D, 0x5E, 0x2D] do
        IO.puts("    >>> LZMA-like properties byte (0x#{Integer.to_string(props, 16)})")
      end
    end

    # CBOR: try to interpret first bytes
    first = hd(bytes)
    cbor_major = first >>> 5
    cbor_info = first &&& 0x1F
    cbor_type_names = %{0 => "uint", 1 => "negint", 2 => "bstr", 3 => "tstr", 4 => "array", 5 => "map", 6 => "tag", 7 => "simple"}
    tname = Map.get(cbor_type_names, cbor_major, "?")
    IO.puts("    CBOR first byte: major=#{cbor_major}(#{tname}) info=#{cbor_info}")

    # Check if data starts with valid protobuf field tags
    wire_type = first &&& 0x07
    field_num = first >>> 3
    pb_valid = wire_type in [0, 1, 2, 5] and field_num > 0
    IO.puts("    protobuf first byte: field=#{field_num} wire_type=#{wire_type} valid=#{pb_valid}")

    # Look for zero bytes — compressed data rarely has long runs of zeros;
    # encrypted data has ~n/256 zeros; raw structured data may have zero padding
    zero_count = Enum.count(bytes, &(&1 == 0))
    expected_zeros = Float.round(n / 256, 1)
    IO.puts("    zero bytes: #{zero_count} (expected ~#{expected_zeros} for random)")

    # Look for byte 0x01 frequency (TLV headers, length prefixes often use small values)
    small_vals = Enum.count(bytes, &(&1 < 0x10))
    IO.puts("    bytes < 0x10: #{small_vals} (expected ~#{Float.round(n * 16 / 256, 1)} for random)")
  end

  # -- Autocorrelation --

  defp autocorrelation_report(label, enc) do
    bytes = :binary.bin_to_list(enc)
    n = length(bytes)
    IO.puts("  #{label} (#{n} bytes):")

    for lag <- [1, 2, 3, 4, 8, 16] do
      if lag < n do
        pairs = Enum.zip(Enum.take(bytes, n - lag), Enum.drop(bytes, lag))
        matches = Enum.count(pairs, fn {a, b} -> a == b end)
        xor_zeros = Enum.count(pairs, fn {a, b} -> bxor(a, b) == 0 end)
        expected = Float.round((n - lag) / 256, 2)
        IO.puts("    lag #{String.pad_leading(Integer.to_string(lag), 2)}: #{matches} matches (expected ~#{expected} for random), xor_zeros=#{xor_zeros}")
      end
    end
  end

  # -- Runs test for randomness --

  defp runs_test_report(label, enc) do
    bytes = :binary.bin_to_list(enc)
    n = length(bytes)
    median = Enum.sort(bytes) |> Enum.at(div(n, 2))
    bits = Enum.map(bytes, fn b -> if b >= median, do: 1, else: 0 end)
    runs = count_runs(bits)
    n1 = Enum.count(bits, &(&1 == 1))
    n0 = n - n1
    expected_runs =
      if n0 > 0 and n1 > 0,
        do: 1 + 2 * n0 * n1 / n,
        else: 1.0
    IO.puts("  #{label}: #{runs} runs (expected ~#{Float.round(expected_runs, 1)} for random, n=#{n}, median=0x#{Integer.to_string(median, 16) |> String.pad_leading(2, "0")})")
  end

  defp count_runs([]), do: 0
  defp count_runs([_]), do: 1
  defp count_runs([a, b | rest]) do
    if a == b, do: count_runs([b | rest]), else: 1 + count_runs([b | rest])
  end

  # -- N-gram frequency --

  defp ngram_report(label, enc) do
    bytes = :binary.bin_to_list(enc)
    n = length(bytes)
    IO.puts("  #{label} (#{n} bytes):")

    for {gram_size, gram_label} <- [{2, "digram"}, {3, "trigram"}] do
      if n >= gram_size do
        grams =
          bytes
          |> Enum.chunk_every(gram_size, 1, :discard)
          |> Enum.frequencies()

        total = n - gram_size + 1
        top =
          grams
          |> Enum.sort_by(fn {_, c} -> -c end)
          |> Enum.take(5)
          |> Enum.map(fn {g, c} ->
            hex = g |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end) |> Enum.join("")
            "#{hex}=#{c}"
          end)
          |> Enum.join(", ")

        max_count = grams |> Map.values() |> Enum.max(fn -> 0 end)
        repeats = grams |> Enum.count(fn {_, c} -> c > 1 end)

        IO.puts("    #{gram_label}: #{map_size(grams)} unique / #{total} total, #{repeats} repeated, max=#{max_count}")
        IO.puts("    top-5: #{top}")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # AES-CCM decryption — BrickNet / ASIC mutual auth only (NOT tag encryption).
  # Tags use Grain-128A. Retained for BrickNet analysis and historical reference.
  # ---------------------------------------------------------------------------

  @ccm_nonce_lengths [7, 8, 10, 11, 12, 13]
  @ccm_mac_lengths [4, 8, 16]

  @doc """
  ARCHIVED: AES-CCM brute force — targets BrickNet/ASIC-auth cipher, NOT tags.

  Tags use Grain-128A (ISO/IEC 29167-13). For active tag decryption, see
  GrainExperiments.run(). This function is retained for investigating
  BrickNet PAwR encryption or as historical reference.

  AES-CCM is authenticated encryption: wrong keys are cryptographically rejected.
  No false positives are possible — a successful decryption is the real key.

  The encrypted region (bytes 5+ of the tag payload) is split as:
    Option A: [ciphertext || MAC]  (nonce derived from UID or header)
    Option B: [nonce || ciphertext || MAC]  (nonce stored on tag)
  """
  def run_aes_ccm(jsonl_path \\ nil) do
    paths = if jsonl_path do
      [jsonl_path]
    else
      data_dir = resolve_data_dir()
      Path.wildcard(Path.join(data_dir, "*.jsonl"))
    end
    tags = Enum.flat_map(paths, &load_tags/1)
    raw_count = length(tags)
    tags = drop_test_tags(tags)
    skipped = raw_count - length(tags)
    if skipped > 0, do: IO.puts("Skipped #{skipped} test tag(s) ([FAIL] / [RED FLASH])\n")
    IO.puts("Loaded #{length(tags)} tag(s) from #{length(paths)} file(s)\n")
    unique = dedupe_by_payload(tags)
    IO.puts("Unique payloads: #{length(unique)}\n")

    keys = load_all_candidate_keys() ++ tag_derived_candidate_keys(unique)
    IO.puts("Loaded #{length(keys)} candidate keys (including tag-derived)\n")

    IO.puts(String.duplicate("=", 70))
    IO.puts("AES-128-CCM BRUTE FORCE")
    IO.puts(String.duplicate("=", 70))

    first_tag = List.first(unique)
    enc = encrypted_binary(first_tag)
    IO.puts("First tag: #{tag_label(first_tag)} (#{byte_size(enc)} enc bytes)\n")

    # Strategy 1: Nonce embedded in encrypted data
    IO.puts("=== Strategy 1: Nonce at start of encrypted data ===")
    IO.puts("  Testing #{length(keys)} keys × #{length(@ccm_nonce_lengths)} nonce_lens × #{length(@ccm_mac_lengths)} mac_lens")
    combos_1 = length(keys) * length(@ccm_nonce_lengths) * length(@ccm_mac_lengths)
    IO.puts("  Total combos: #{combos_1}\n")

    hit1 = try_ccm_embedded_nonce(unique, keys)

    # Strategy 2: Nonce derived from UID
    IO.puts("\n=== Strategy 2: Nonce derived from UID ===")
    hit2 = try_ccm_uid_nonce(unique, keys)

    # Strategy 3: Nonce derived from header (block 0)
    IO.puts("\n=== Strategy 3: Nonce derived from header ===")
    hit3 = try_ccm_header_nonce(unique, keys)

    # Strategy 4: Nonce = zeros
    IO.puts("\n=== Strategy 4: Fixed nonce (all zeros) ===")
    hit4 = try_ccm_fixed_nonce(unique, keys)

    # Strategy 5: MAC at start
    IO.puts("\n=== Strategy 5: MAC at start of encrypted region ===")
    hit5 = try_ccm_mac_at_start(unique, keys)

    # Strategy 6: Nonce = hash(header)
    IO.puts("\n=== Strategy 6: Nonce = hash(cleartext header) ===")
    hit6 = try_ccm_nonce_hash_header(unique, keys)

    # Strategy 7: Nonce = hash(category)
    IO.puts("\n=== Strategy 7: Nonce = hash(category) ===")
    hit7 = try_ccm_nonce_hash_category(unique, keys)

    # Strategy 8: Nonce = payload_len + zeros
    IO.puts("\n=== Strategy 8: Nonce = payload_len + zeros ===")
    hit8 = try_ccm_nonce_payload_len(unique, keys)

    # AES-GCM and ChaCha20-Poly1305 (sanity check)
    IO.puts("\n=== Strategy 9: AES-128-GCM ===")
    hit9 = try_aead_gcm(unique, keys)

    IO.puts("\n=== Strategy 10: ChaCha20-Poly1305 ===")
    hit10 = try_aead_chacha20(unique, keys)

    any_hit = hit1 || hit2 || hit3 || hit4 || hit5 || hit6 || hit7 || hit8 || hit9 || hit10
    IO.puts("\n" <> String.duplicate("=", 70))
    if any_hit do
      IO.puts("SUCCESS: AES-CCM key found! See HIT lines above.")
    else
      IO.puts("No AES-CCM key found with #{length(keys)} candidates.")
      IO.puts("The key may be:")
      IO.puts("  - Burned into OTP/secure element (not in firmware binary)")
      IO.puts("  - Derived at runtime (session key from cloud)")
      IO.puts("  - Using a different nonce construction")
    end
    IO.puts(String.duplicate("=", 70))
  end

  defp load_all_candidate_keys do
    fw_keys = load_firmware_candidate_keys()
    builtin = candidate_keys()
    all = (builtin ++ fw_keys) |> Enum.uniq()
    all
  end

  # Keys derived from tag constants (magic, header, 0x010C) for tags-only attacks
  defp tag_derived_candidate_keys(tags) do
    first = List.first(tags)

    keys = [
      :crypto.hash(:sha256, @identity_event_magic) |> binary_part(0, 16),
      :crypto.hash(:sha256, @item_event_magic) |> binary_part(0, 16),
      :crypto.hash(:sha256, <<0x01, 0x0C>>) |> binary_part(0, 16),
      :crypto.hash(:sha256, "identity") |> binary_part(0, 16),
      :crypto.hash(:sha256, "item") |> binary_part(0, 16),
      pad16("0x010C"),
      pad16(<<0x01, 0x0C>>),
    ]

    extra = if first do
      header5 = cleartext_header(first)
      block0 = Enum.at(first["blocks"], 0) || "00000000"
      block0_bin = Base.decode16!(String.pad_trailing(String.upcase(block0), 8, "0"), case: :mixed)
      [
        :crypto.hash(:sha256, header5) |> binary_part(0, 16),
        :crypto.hash(:sha256, block0_bin) |> binary_part(0, 16),
      ]
    else
      []
    end

    (keys ++ extra) |> Enum.uniq()
  end

  defp load_firmware_candidate_keys do
    data_dir = resolve_data_dir()
    path = Path.join(data_dir, "candidate_keys.json")
    if File.exists?(path) do
      case File.read!(path) |> JSON.decode() do
        {:ok, data} ->
          keys = []
          keys = keys ++ extract_hex_keys(data["universal_keys"] || [])
          keys = keys ++ extract_hex_keys(data["rkey_vicinity_keys"] || [])
          keys = keys ++ extract_hex_keys(data["top_entropy_keys"] || [])
          keys = keys ++ extract_hex_keys(data["special_candidates"] || [])
          keys |> Enum.uniq()
        {:error, _} ->
          IO.puts("  Warning: could not parse #{path}")
          []
      end
    else
      IO.puts("  Warning: #{path} not found (run firmware/extract_keys.py first)")
      []
    end
  end

  defp extract_hex_keys(list) when is_list(list) do
    Enum.flat_map(list, fn
      %{"hex" => hex} when is_binary(hex) and byte_size(hex) == 32 ->
        case Base.decode16(String.upcase(hex), case: :mixed) do
          {:ok, key} -> [key]
          _ -> []
        end
      _ -> []
    end)
  end

  # Generate n random 16-byte keys for CCM brute-force (payload is AES-CCM, not ECB).
  defp generate_random_keys(n) when is_integer(n) and n > 0 do
    for _ <- 1..n, do: :crypto.strong_rand_bytes(16)
  end

  # Try many random keys with CCM strategies (embedded nonce first, then header nonce).
  defp try_ccm_random_keys(tags, num_keys) do
    keys = generate_random_keys(num_keys)
    IO.puts("  Trying #{num_keys} random keys with CCM embedded-nonce strategy...")
    hit = try_ccm_embedded_nonce(tags, keys)
    if hit do
      hit
    else
      IO.puts("  No hit; trying same keys with CCM header-nonce strategy...")
      try_ccm_header_nonce(tags, keys)
    end
  end

  # Strategy 1: [nonce (N bytes) | ciphertext | MAC (M bytes)] all within enc
  defp try_ccm_embedded_nonce(tags, keys) do
    first_tag = List.first(tags)
    enc = encrypted_binary(first_tag)
    enc_len = byte_size(enc)

    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          min_data = nonce_len + mac_len + 1
          if enc_len < min_data do
            nil
          else
            Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
              nonce = binary_part(enc, 0, nonce_len)
              ciphertext = binary_part(enc, nonce_len, enc_len - nonce_len - mac_len)
              mac = binary_part(enc, enc_len - mac_len, mac_len)
              aad = aad_fn.(first_tag)

              case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                {:ok, _plaintext} ->
                  {pass, total} = validate_ccm_on_all(tags, key, nonce_len, mac_len, aad_fn)
                  if pass >= 1 do
                    report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "embedded_nonce", pass, total, tags)
                    true
                  end
                _ -> nil
              end
            end)
          end
        end)
      end)
    end)

    unless hit, do: IO.puts("  No hits with embedded nonce strategy")
    hit
  end

  # Strategy 2: Nonce = f(UID)
  defp try_ccm_uid_nonce(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
            results = Enum.map(tags, fn tag ->
              enc = encrypted_binary(tag)
              enc_len = byte_size(enc)
              if enc_len < mac_len + 1 do
                :skip
              else
                nonce = uid_to_nonce(tag, nonce_len)
                ciphertext = binary_part(enc, 0, enc_len - mac_len)
                mac = binary_part(enc, enc_len - mac_len, mac_len)
                aad = aad_fn.(tag)

                case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                  {:ok, _} -> :pass
                  _ -> :fail
                end
              end
            end)

            pass = Enum.count(results, &(&1 == :pass))
            if pass >= max(1, div(length(tags), 2)) do
              report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "uid_nonce", pass, length(tags), tags)
              true
            end
          end)
        end)
      end)
    end)

    unless hit, do: IO.puts("  No hits with UID-derived nonce strategy")
    hit
  end

  # Strategy 3: Nonce derived from header bytes
  defp try_ccm_header_nonce(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
            results = Enum.map(tags, fn tag ->
              enc = encrypted_binary(tag)
              enc_len = byte_size(enc)
              if enc_len < mac_len + 1 do
                :skip
              else
                nonce = header_to_nonce(tag, nonce_len)
                ciphertext = binary_part(enc, 0, enc_len - mac_len)
                mac = binary_part(enc, enc_len - mac_len, mac_len)
                aad = aad_fn.(tag)

                case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                  {:ok, _} -> :pass
                  _ -> :fail
                end
              end
            end)

            pass = Enum.count(results, &(&1 == :pass))
            if pass >= max(1, div(length(tags), 2)) do
              report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "header_nonce", pass, length(tags), tags)
              true
            end
          end)
        end)
      end)
    end)

    unless hit, do: IO.puts("  No hits with header-derived nonce strategy")
    hit
  end

  # Strategy 4: Fixed nonce (all zeros, useful as baseline)
  defp try_ccm_fixed_nonce(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
            nonce = :binary.copy(<<0>>, nonce_len)

            results = Enum.map(tags, fn tag ->
              enc = encrypted_binary(tag)
              enc_len = byte_size(enc)
              if enc_len < mac_len + 1 do
                :skip
              else
                ciphertext = binary_part(enc, 0, enc_len - mac_len)
                mac = binary_part(enc, enc_len - mac_len, mac_len)
                aad = aad_fn.(tag)

                case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                  {:ok, _} -> :pass
                  _ -> :fail
                end
              end
            end)

            pass = Enum.count(results, &(&1 == :pass))
            if pass >= 1 do
              report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "fixed_zeros", pass, length(tags), tags)
              true
            end
          end)
        end)
      end)
    end)

    unless hit, do: IO.puts("  No hits with fixed zero nonce strategy")
    hit
  end

  # Strategy 5: MAC at start of encrypted region — [MAC | nonce | ciphertext]
  defp try_ccm_mac_at_start(tags, keys) do
    first_tag = List.first(tags)
    enc = encrypted_binary(first_tag)
    enc_len = byte_size(enc)

    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          min_data = mac_len + nonce_len + mac_len + 1
          if enc_len < min_data do
            nil
          else
            Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
              mac = binary_part(enc, 0, mac_len)
              nonce = binary_part(enc, mac_len, nonce_len)
              ciphertext = binary_part(enc, mac_len + nonce_len, enc_len - mac_len - nonce_len)
              aad = aad_fn.(first_tag)

              case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                {:ok, _plaintext} ->
                  {pass, total} = validate_ccm_mac_at_start(tags, key, nonce_len, mac_len, aad_fn)
                  if pass >= 1 do
                    report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "mac_at_start", pass, total, tags)
                    true
                  end
                _ -> nil
              end
            end)
          end
        end)
      end)
    end)

    unless hit, do: IO.puts("  No hits with MAC-at-start strategy")
    hit
  end

  defp validate_ccm_mac_at_start(tags, key, nonce_len, mac_len, aad_fn) do
    results = Enum.map(tags, fn tag ->
      enc = encrypted_binary(tag)
      enc_len = byte_size(enc)
      if enc_len < mac_len + nonce_len + mac_len + 1 do
        :skip
      else
        mac = binary_part(enc, 0, mac_len)
        nonce = binary_part(enc, mac_len, nonce_len)
        ciphertext = binary_part(enc, mac_len + nonce_len, enc_len - mac_len - nonce_len)
        aad = aad_fn.(tag)
        case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
          {:ok, _} -> :pass
          _ -> :fail
        end
      end
    end)
    pass = Enum.count(results, &(&1 == :pass))
    total = Enum.count(results, &(&1 != :skip))
    {pass, total}
  end

  # Nonce = first N bytes of hash(header)
  defp nonce_hash_header(tag, nonce_len) do
    h = cleartext_header(tag)
    hash = :crypto.hash(:sha256, h)
    binary_part(hash, 0, min(nonce_len, byte_size(hash)))
  end

  # Nonce = first N bytes of hash("identity") or hash("item")
  defp nonce_hash_category(tag, nonce_len) do
    cat = case tag_category(tag) do
      :identity -> "identity"
      :item -> "item"
      _ -> "unknown"
    end
    hash = :crypto.hash(:sha256, cat)
    binary_part(hash, 0, min(nonce_len, byte_size(hash)))
  end

  # Nonce = payload_len (2 bytes) + zeros to nonce_len
  defp nonce_payload_len(tag, nonce_len) do
    hex = Enum.at(tag["blocks"], 0) || "00000000"
    bin = Base.decode16!(String.pad_trailing(String.upcase(hex), 8, "0"), case: :mixed)
    len_2 = if byte_size(bin) >= 2, do: binary_part(bin, 0, 2), else: <<0, 0>>
    pad = nonce_len - 2
    if pad <= 0 do
      binary_part(len_2, 0, nonce_len)
    else
      len_2 <> :binary.copy(<<0>>, pad)
    end
  end

  # Strategy 6: Nonce = hash(cleartext header) truncated
  defp try_ccm_nonce_hash_header(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
            results = Enum.map(tags, fn tag ->
              enc = encrypted_binary(tag)
              enc_len = byte_size(enc)
              if enc_len < mac_len + 1 do
                :skip
              else
                nonce = nonce_hash_header(tag, nonce_len)
                ciphertext = binary_part(enc, 0, enc_len - mac_len)
                mac = binary_part(enc, enc_len - mac_len, mac_len)
                aad = aad_fn.(tag)
                case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                  {:ok, _} -> :pass
                  _ -> :fail
                end
              end
            end)
            pass = Enum.count(results, &(&1 == :pass))
            if pass >= max(1, div(length(tags), 2)) do
              report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "hash_header", pass, length(tags), tags)
              true
            end
          end)
        end)
      end)
    end)
    unless hit, do: IO.puts("  No hits with nonce=hash(header) strategy")
    hit
  end

  # Strategy 7: Nonce = hash(category) truncated
  defp try_ccm_nonce_hash_category(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
            results = Enum.map(tags, fn tag ->
              enc = encrypted_binary(tag)
              enc_len = byte_size(enc)
              if enc_len < mac_len + 1 do
                :skip
              else
                nonce = nonce_hash_category(tag, nonce_len)
                ciphertext = binary_part(enc, 0, enc_len - mac_len)
                mac = binary_part(enc, enc_len - mac_len, mac_len)
                aad = aad_fn.(tag)
                case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                  {:ok, _} -> :pass
                  _ -> :fail
                end
              end
            end)
            pass = Enum.count(results, &(&1 == :pass))
            if pass >= max(1, div(length(tags), 2)) do
              report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "hash_category", pass, length(tags), tags)
              true
            end
          end)
        end)
      end)
    end)
    unless hit, do: IO.puts("  No hits with nonce=hash(category) strategy")
    hit
  end

  # Strategy 8: Nonce = payload_len (2 bytes) + zeros
  defp try_ccm_nonce_payload_len(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@ccm_nonce_lengths, fn nonce_len ->
        Enum.find_value(@ccm_mac_lengths, fn mac_len ->
          Enum.find_value(ccm_aad_options(), fn {aad_name, aad_fn} ->
            results = Enum.map(tags, fn tag ->
              enc = encrypted_binary(tag)
              enc_len = byte_size(enc)
              if enc_len < mac_len + 1 do
                :skip
              else
                nonce = nonce_payload_len(tag, nonce_len)
                ciphertext = binary_part(enc, 0, enc_len - mac_len)
                mac = binary_part(enc, enc_len - mac_len, mac_len)
                aad = aad_fn.(tag)
                case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
                  {:ok, _} -> :pass
                  _ -> :fail
                end
              end
            end)
            pass = Enum.count(results, &(&1 == :pass))
            if pass >= max(1, div(length(tags), 2)) do
              report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, "payload_len_nonce", pass, length(tags), tags)
              true
            end
          end)
        end)
      end)
    end)
    unless hit, do: IO.puts("  No hits with nonce=payload_len+zeros strategy")
    hit
  end

  # Strategy 9: AES-128-GCM (same nonce/layout ideas as CCM)
  @gcm_iv_lengths [12]
  @gcm_tag_lengths [16, 12]

  defp try_aead_gcm(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      Enum.find_value(@gcm_iv_lengths, fn iv_len ->
        Enum.find_value(@gcm_tag_lengths, fn tag_len ->
          results = Enum.map(tags, fn tag ->
            enc = encrypted_binary(tag)
            enc_len = byte_size(enc)
            if enc_len < iv_len + tag_len + 1 do
              :skip
            else
              iv = header_to_nonce(tag, iv_len)
              ciphertext = binary_part(enc, 0, enc_len - tag_len)
              tag_bin = binary_part(enc, enc_len - tag_len, tag_len)
              case gcm_decrypt(key, iv, ciphertext, <<>>, tag_bin) do
                {:ok, _} -> :pass
                _ -> :fail
              end
            end
          end)
          pass = Enum.count(results, &(&1 == :pass))
          if pass >= max(1, div(length(tags), 2)) do
            IO.puts("  !!! AES-GCM HIT: iv=header(#{iv_len}) tag=#{tag_len} pass=#{pass}/#{length(tags)}")
            true
          end
        end)
      end)
    end)
    unless hit, do: IO.puts("  No hits with AES-GCM")
    hit
  end

  defp gcm_decrypt(key, iv, ciphertext, aad, tag) do
    try do
      case :crypto.crypto_one_time_aead(:aes_128_gcm, key, iv, ciphertext, aad, tag, false) do
        :error -> :error
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
      end
    rescue
      _ -> :error
    catch
      _, _ -> :error
    end
  end

  # Strategy 10: ChaCha20-Poly1305 (12-byte nonce, 16-byte tag; key must be 32 bytes)
  defp try_aead_chacha20(tags, keys) do
    hit = Enum.find_value(keys, fn key ->
      key32 = if byte_size(key) == 16, do: key <> :binary.copy(<<0>>, 16), else: key
      if byte_size(key32) != 32 do
        nil
      else
        results = Enum.map(tags, fn tag ->
          enc = encrypted_binary(tag)
          enc_len = byte_size(enc)
          if enc_len < 12 + 16 + 1 do
            :skip
          else
            nonce = header_to_nonce(tag, 12)
            ciphertext = binary_part(enc, 0, enc_len - 16)
            tag_bin = binary_part(enc, enc_len - 16, 16)
            case chacha20_decrypt(key32, nonce, ciphertext, <<>>, tag_bin) do
              {:ok, _} -> :pass
              _ -> :fail
            end
          end
        end)
        pass = Enum.count(results, &(&1 == :pass))
        if pass >= max(1, div(length(tags), 2)) do
          IO.puts("  !!! ChaCha20-Poly1305 HIT: pass=#{pass}/#{length(tags)}")
          true
        end
      end
    end)
    unless hit, do: IO.puts("  No hits with ChaCha20-Poly1305")
    hit
  end

  defp chacha20_decrypt(key, nonce, ciphertext, aad, tag) when byte_size(key) == 32 do
    try do
      case :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ciphertext, aad, tag, false) do
        :error -> :error
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
      end
    rescue
      _ -> :error
    catch
      _, _ -> :error
    end
  end

  defp ccm_decrypt(key, nonce, ciphertext, aad, mac) do
    try do
      case :crypto.crypto_one_time_aead(:aes_128_ccm, key, nonce,
                                         ciphertext, aad, mac, false) do
        :error -> :error
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
      end
    rescue
      _ -> :error
    catch
      _, _ -> :error
    end
  end

  defp validate_ccm_on_all(tags, key, nonce_len, mac_len, aad_fn) do
    results = Enum.map(tags, fn tag ->
      enc = encrypted_binary(tag)
      enc_len = byte_size(enc)
      if enc_len < nonce_len + mac_len + 1 do
        :skip
      else
        nonce = binary_part(enc, 0, nonce_len)
        ciphertext = binary_part(enc, nonce_len, enc_len - nonce_len - mac_len)
        mac = binary_part(enc, enc_len - mac_len, mac_len)
        aad = aad_fn.(tag)

        case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
          {:ok, _} -> :pass
          _ -> :fail
        end
      end
    end)
    pass = Enum.count(results, &(&1 == :pass))
    total = Enum.count(results, &(&1 != :skip))
    {pass, total}
  end

  defp uid_to_nonce(tag, nonce_len) do
    uid_hex = tag["uid"]
    uid_bytes = Base.decode16!(String.upcase(uid_hex), case: :mixed)
    # Pad or truncate UID to nonce_len
    if byte_size(uid_bytes) >= nonce_len do
      binary_part(uid_bytes, 0, nonce_len)
    else
      uid_bytes <> :binary.copy(<<0>>, nonce_len - byte_size(uid_bytes))
    end
  end

  defp header_to_nonce(tag, nonce_len) do
    hex = Enum.at(tag["blocks"], 0) || "00000000"
    header = Base.decode16!(String.upcase(hex), case: :mixed)
    # Use header + 0x01 format byte as nonce source, pad to nonce_len
    source = header <> <<0x01>>
    if byte_size(source) >= nonce_len do
      binary_part(source, 0, nonce_len)
    else
      source <> :binary.copy(<<0>>, nonce_len - byte_size(source))
    end
  end

  # Full 5-byte cleartext header: block0 (4 bytes) + format byte 0x01
  defp cleartext_header(tag) do
    hex = Enum.at(tag["blocks"], 0) || "00000000"
    block0 = Base.decode16!(String.pad_trailing(String.upcase(hex), 8, "0"), case: :mixed)
    block0 <> <<0x01>>
  end

  # AAD options used across CCM strategies (name, fn tag -> aad_binary)
  defp ccm_aad_options do
    [
      {"empty", fn _tag -> <<>> end},
      {"header4", fn tag ->
        hex = Enum.at(tag["blocks"], 0) || "00000000"
        Base.decode16!(String.pad_trailing(String.upcase(hex), 8, "0"), case: :mixed)
      end},
      {"header5", fn tag -> cleartext_header(tag) end},
      {"format_byte", fn _tag -> <<0x01>> end},
      {"payload_len_x8", fn tag ->
        hex = Enum.at(tag["blocks"], 0) || "00000000"
        bin = Base.decode16!(String.pad_trailing(String.upcase(hex), 8, "0"), case: :mixed)
        len_2 = if byte_size(bin) >= 2, do: binary_part(bin, 0, 2), else: <<0, 0>>
        :binary.copy(len_2, 8)
      end},
      {"payload_len_x4", fn tag ->
        hex = Enum.at(tag["blocks"], 0) || "00000000"
        bin = Base.decode16!(String.pad_trailing(String.upcase(hex), 8, "0"), case: :mixed)
        len_2 = if byte_size(bin) >= 2, do: binary_part(bin, 0, 2), else: <<0, 0>>
        :binary.copy(len_2, 4)
      end},
    ]
  end

  defp report_ccm_hit(key, nonce_len, mac_len, aad_fn, aad_name, strategy, pass, total, tags) do
    key_hex = Base.encode16(key, case: :lower)
    IO.puts("\n  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    IO.puts("  !!! AES-CCM HIT: #{strategy} !!!")
    IO.puts("  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    IO.puts("  Key (hex):    #{key_hex}")
    IO.puts("  Nonce length: #{nonce_len}")
    IO.puts("  MAC length:   #{mac_len}")
    IO.puts("  AAD:          #{aad_name}")
    IO.puts("  Validated:    #{pass}/#{total} tags\n")

    # Show decrypted data for each tag
    Enum.each(tags, fn tag ->
      enc = encrypted_binary(tag)
      enc_len = byte_size(enc)
      aad = aad_fn.(tag)

      {nonce, ciphertext, mac} = case strategy do
        "embedded_nonce" ->
          {binary_part(enc, 0, nonce_len),
           binary_part(enc, nonce_len, enc_len - nonce_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        "mac_at_start" ->
          mac = binary_part(enc, 0, mac_len)
          nonce = binary_part(enc, mac_len, nonce_len)
          ct = binary_part(enc, mac_len + nonce_len, enc_len - mac_len - nonce_len)
          {nonce, ct, mac}
        "uid_nonce" ->
          {uid_to_nonce(tag, nonce_len),
           binary_part(enc, 0, enc_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        "header_nonce" ->
          {header_to_nonce(tag, nonce_len),
           binary_part(enc, 0, enc_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        "fixed_zeros" ->
          {:binary.copy(<<0>>, nonce_len),
           binary_part(enc, 0, enc_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        "hash_header" ->
          {nonce_hash_header(tag, nonce_len),
           binary_part(enc, 0, enc_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        "hash_category" ->
          {nonce_hash_category(tag, nonce_len),
           binary_part(enc, 0, enc_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        "payload_len_nonce" ->
          {nonce_payload_len(tag, nonce_len),
           binary_part(enc, 0, enc_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
        _ ->
          {binary_part(enc, 0, nonce_len),
           binary_part(enc, nonce_len, enc_len - nonce_len - mac_len),
           binary_part(enc, enc_len - mac_len, mac_len)}
      end

      case ccm_decrypt(key, nonce, ciphertext, aad, mac) do
        {:ok, plaintext} ->
          hex = plaintext |> binary_part(0, min(32, byte_size(plaintext)))
                |> :binary.bin_to_list()
                |> Enum.map(fn b -> Integer.to_string(b, 16) |> String.pad_leading(2, "0") end)
                |> Enum.join(" ")
          ascii = plaintext |> binary_part(0, min(32, byte_size(plaintext)))
                  |> :binary.bin_to_list()
                  |> Enum.map(fn b -> if b >= 0x20 and b <= 0x7E, do: <<b>>, else: "." end)
                  |> Enum.join()
          IO.puts("  #{tag_label(tag)}:")
          IO.puts("    decrypted (first 32): #{hex}")
          IO.puts("    ascii:                #{ascii}")
        _ ->
          IO.puts("  #{tag_label(tag)}: FAILED to decrypt")
      end
    end)
  end

end
