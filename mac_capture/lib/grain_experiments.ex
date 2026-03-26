defmodule GrainExperiments do
  @moduledoc """
  Grain-128A tag decryption experiments for LEGO Smart Brick NFC tags.

  Based on findings from node-smartplay HARDWARE.md (2026-03-17):
  - Tag encryption is Grain-128A (ISO/IEC 29167-13), NOT AES-CCM
  - AES-CCM in the EM9305 firmware is for BrickNet PAwR / ASIC mutual auth
  - The DA000001-01 ASIC decrypts tags; the key is in ASIC silicon
  - Tag IC is EM4237 (IC ref 0x17), which implements Grain-128A

  Hypothesized tag layout:
    [00 LEN 01 0C] [01] [IV: 12 bytes] [ciphertext] [MAC: 0-8 bytes]
     cleartext hdr  fmt   encrypted payload (starts at byte 5)

  The first 12 bytes of the encrypted region are a per-content IV.
  Same content → same IV → same ciphertext (UID-independent).

  Run experiments:
    cd mac_capture
    mix run -e "GrainExperiments.run()"
    mix run -e "GrainExperiments.self_test()"
    mix run -e "GrainExperiments.run_known_plaintext()"
  """

  @cleartext_header_size 5
  @iv_size 12

  # Known plaintext bytes for 4 ship tags (90-byte plaintext each).
  # From node-smartplay HARDWARE.md "Tag Encryption Investigation".
  # These are firm known bytes at specific plaintext offsets in the
  # decrypted content (after IV, before optional MAC).
  @known_pt_bytes %{
    53 => 0x03,  # timer sub-record length
    54 => 0x18,  # timer content_ref lo (script #42, param=24)
    55 => 0x00,  # timer content_ref hi
    59 => 0x10,  # button sub-record length (16-byte payload)
    60 => 0x04,  # button framing byte
    63 => 0x02,  # button inner_type (resource ref)
    64 => 0x12,  # button tag_byte
    66 => 0x08,  # button sub_type lo (0x0008)
    67 => 0x00,  # button sub_type hi
    69 => 0x00   # button content_ref hi
  }

  # Known keystream bytes from node-smartplay (ciphertext XOR known plaintext).
  # Each map: %{pt_offset => expected_keystream_byte}
  # The ciphertext offset = IV_SIZE + pt_offset (since IV precedes ciphertext).
  @ship_keystream %{
    "x-wing" => %{53=>0x07, 54=>0x00, 55=>0x02, 59=>0x51, 60=>0xCD,
                   63=>0xAC, 64=>0xD3, 66=>0xD4, 67=>0x92, 69=>0x8E},
    "tie"    => %{53=>0xDD, 54=>0x78, 55=>0x9B, 59=>0x78, 60=>0x14,
                   63=>0xCE, 64=>0xE2, 66=>0x3D, 67=>0x1B, 69=>0xBC},
    "falcon" => %{53=>0x79, 54=>0xF5, 55=>0xD4, 59=>0x09, 60=>0xC7,
                   63=>0x21, 64=>0xBF, 66=>0xD1, 67=>0x40, 69=>0x94},
    "a-wing" => %{53=>0xF5, 54=>0x85, 55=>0xF0, 59=>0x18, 60=>0xB3,
                   63=>0xB7, 64=>0xF7, 66=>0x0B, 67=>0x31, 69=>0xE6}
  }

  # Plaintext sizes for all known tags (encrypted bytes after IV, before MAC).
  # From node-smartplay plaintext structure analysis.
  @tag_pt_sizes %{
    "R2-D2" => 57, "Fuel Cargo" => 84, "X-Wing" => 90, "TIE Fighter" => 90,
    "Falcon" => 90, "A-Wing" => 90, "Han Solo" => 96, "Hyperdrive" => 92,
    "Chewbacca" => 99, "C-3PO" => 101, "Lightsaber" => 109,
    "Luke" => 140, "Leia" => 141, "Vader" => 152, "Palpatine" => 154
  }

  # ---------- Extended known plaintext model ----------
  #
  # Sub-record structural constants from HARDWARE.md dispatch chain trace.
  # These bytes have the same value in EVERY tag that contains the record type,
  # regardless of which character/item the tag represents.
  #
  # Raw sub-record format for resource refs:
  #   +0: type (u8)           — varies
  #   +1: param (s8)          — varies
  #   +2: length (u8)         = 0x10 for button/npm resource refs
  #   +3: framing             = 0x04
  #   +4-5: inner length      — likely fixed but unconfirmed
  #   +6: inner_type          = 0x02 (resource ref)
  #   +7: tag_byte            = 0x12
  #   +8: unknown
  #   +9: sub_type lo         = 0x08
  #   +10: sub_type hi        = 0x00
  #   +11: content_ref lo     — varies per tag
  #   +12: content_ref hi     = 0x00 (all script params < 256)
  #
  # timer_ref (6 bytes, compact):
  #   +0: type, +1: param, +2: length = 0x03, +3: content_ref lo, +4: content_ref hi = 0x00, +5: ???
  #

  # Structural known bytes within a timer_ref sub-record (relative to record start)
  @timer_struct %{2 => 0x03, 4 => 0x00}

  # Structural known bytes within a button_ref sub-record (relative to record start)
  @button_struct %{2 => 0x10, 3 => 0x04, 6 => 0x02, 7 => 0x12, 9 => 0x08, 10 => 0x00, 12 => 0x00}

  # Validated plaintext decompositions: tag category → record layout.
  # Each record is {name, start_offset, size}. "✓" = exact size match from HARDWARE.md.
  # Only tags with exact model match are included; ~close matches are excluded.
  @tag_layouts %{
    # Items (identity_block = 51 bytes)
    :item_ship     => %{id_block: 51, records: [{:timer, 51, 6}, {:button, 57, 33}]},     # 90 PT ✓
    :item_fuel     => %{id_block: 51, records: [{:button, 51, 33}]},                        # 84 PT ✓
    :item_r2d2     => %{id_block: 57, records: []},                                         # 57 PT ✓ (identity-sized!)
    # Identities (identity_block = 57 bytes)
    :id_basic      => %{id_block: 57, records: [{:timer, 57, 6}, {:button, 63, 33}]},      # 96 PT ✓
    :id_with_npm   => %{id_block: 57, records: [{:timer, 57, 6}, {:button, 63, 33}]},      # 96+npm PT ✓
  }

  # Map tag names to their validated layout type.
  # Only exact-match tags from HARDWARE.md table (✓ rows).
  @tag_layout_map %{
    "x-wing"    => :item_ship,
    "tie"       => :item_ship,
    "falcon"    => :item_ship,
    "a-wing"    => :item_ship,
    "fuel"      => :item_fuel,
    "r2-d2"     => :item_r2d2,
    "han"       => :id_basic,
    "luke"      => :id_with_npm,
    "leia"      => :id_with_npm,
    "vader"     => :id_with_npm,
    "palpatine" => :id_with_npm,
  }

  # ---- Tag Data Helpers ----

  def run(data_dir \\ nil) do
    data_dir = data_dir || resolve_data_dir()
    tags = load_all_tags(data_dir)

    IO.puts("Loaded #{length(tags)} tag(s), #{length(unique_tags(tags))} unique\n")

    IO.puts(String.duplicate("=", 70))
    IO.puts("GRAIN-128A TAG EXPERIMENTS")
    IO.puts(String.duplicate("=", 70))

    IO.puts("\n=== 1. Cipher self-test ===")
    Grain128a.self_test()

    unique = unique_tags(tags)

    IO.puts("\n=== 2. Tag layout analysis ===")
    analyze_tag_layout(unique)

    IO.puts("\n=== 3. IV uniqueness check ===")
    check_iv_uniqueness(unique)

    IO.puts("\n=== 4. Cross-tag XOR analysis (encrypted regions) ===")
    xor_analysis(unique)

    IO.puts("\n=== 5. Known plaintext keystream verification (ships) ===")
    run_known_plaintext()

    IO.puts("\n=== 6. Extended known plaintext (all tags) ===")
    run_extended_known_plaintext(unique)

    IO.puts("\n=== 7. Key candidate search ===")
    search_key_candidates(unique)
  end

  def self_test do
    Grain128a.self_test()
  end

  # ---- Tag Layout Analysis ----

  defp analyze_tag_layout(tags) do
    Enum.each(tags, fn tag ->
      label = tag_label(tag)
      full = full_payload(tag)
      plen = payload_length(tag)
      enc = encrypted_region(tag)
      enc_len = byte_size(enc)

      if enc_len > @iv_size do
        iv = binary_part(enc, 0, @iv_size)
        ct = binary_part(enc, @iv_size, enc_len - @iv_size)
        pt_size_note = find_expected_pt_size(label, byte_size(ct))
        IO.puts("  #{label}")
        IO.puts("    payload_len=#{plen}  enc_region=#{enc_len}  IV=#{Base.encode16(iv)}")
        IO.puts("    ciphertext=#{byte_size(ct)} bytes#{pt_size_note}  header=#{Base.encode16(binary_part(full, 0, min(5, byte_size(full))))}")
      else
        IO.puts("  #{label}: enc_region too short (#{enc_len} bytes)")
      end
    end)
  end

  # ---- IV Uniqueness ----

  defp check_iv_uniqueness(tags) do
    ivs =
      tags
      |> Enum.filter(fn t -> byte_size(encrypted_region(t)) > @iv_size end)
      |> Enum.map(fn t ->
        enc = encrypted_region(t)
        {tag_label(t), binary_part(enc, 0, @iv_size)}
      end)

    unique_ivs = ivs |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length()
    IO.puts("  #{length(ivs)} tags with IV, #{unique_ivs} unique IVs")

    if unique_ivs == length(ivs) do
      IO.puts("  All IVs are unique per content (consistent with per-content IV hypothesis)")
    else
      dupes =
        ivs
        |> Enum.group_by(&elem(&1, 1))
        |> Enum.filter(fn {_, v} -> length(v) > 1 end)

      Enum.each(dupes, fn {iv, entries} ->
        names = Enum.map(entries, fn {n, _} -> n end) |> Enum.join(", ")
        IO.puts("  SHARED IV #{Base.encode16(iv)}: #{names}")
      end)
    end
  end

  # ---- XOR Analysis ----

  defp xor_analysis(tags) do
    regions =
      tags
      |> Enum.filter(fn t -> byte_size(encrypted_region(t)) > @iv_size end)
      |> Enum.map(fn t ->
        enc = encrypted_region(t)
        ct = binary_part(enc, @iv_size, byte_size(enc) - @iv_size)
        {tag_label(t), ct}
      end)

    if length(regions) < 2 do
      IO.puts("  (need >= 2 tags with encrypted payload)")
    else
      pairs = for {a, i} <- Enum.with_index(regions),
                  {b, j} <- Enum.with_index(regions),
                  i < j, do: {a, b}

      IO.puts("  #{length(pairs)} pair(s) to analyze")

      zero_count =
        Enum.count(pairs, fn {{_, ct_a}, {_, ct_b}} ->
          n = min(byte_size(ct_a), byte_size(ct_b))
          xor_bin = :crypto.exor(binary_part(ct_a, 0, n), binary_part(ct_b, 0, n))
          leading_zeros(xor_bin) > 0
        end)

      IO.puts("  Pairs with leading zero bytes in XOR: #{zero_count}")

      if zero_count == 0 do
        IO.puts("  No shared keystream found (consistent with per-content IV)")
      end

      [{a, b} | _] = pairs
      print_xor_pair(a, b)

      if length(pairs) > 1 do
        print_xor_pair(elem(List.first(regions), 0) |> then(fn _ -> List.first(regions) end),
                       List.last(regions))
      end
    end
  end

  defp print_xor_pair({label_a, ct_a}, {label_b, ct_b}) do
    n = min(byte_size(ct_a), byte_size(ct_b))
    xor_bin = :crypto.exor(binary_part(ct_a, 0, n), binary_part(ct_b, 0, n))
    lz = leading_zeros(xor_bin)
    entropy = byte_entropy(xor_bin)

    IO.puts("  #{label_a} vs #{label_b}")
    IO.puts("    common=#{n} bytes  leading_zeros=#{lz}  entropy=#{Float.round(entropy, 2)} bits/byte")
    IO.puts("    XOR[0..31]: #{Base.encode16(binary_part(xor_bin, 0, min(32, n)))}")
  end

  # ---- Known Plaintext Keystream Verification ----

  @doc """
  Test candidate keys against the 40 known keystream bytes from 4 ship tags.
  If a key produces keystream matching all 40 constraints, it's the correct key.

  Run: mix run -e "GrainExperiments.run_known_plaintext()"
  """
  def run_known_plaintext(data_dir \\ nil) do
    data_dir = data_dir || resolve_data_dir()
    tags = load_all_tags(data_dir) |> unique_tags()

    ship_tags = find_ship_tags(tags)

    if map_size(ship_tags) == 0 do
      IO.puts("  No ship tags found in data (need X-Wing, TIE, Falcon, or A-Wing)")
      IO.puts("  Verifying known keystream data standalone...")
      verify_known_keystream_standalone()
      return()
    end

    IO.puts("  Found #{map_size(ship_tags)} ship tag(s): #{Map.keys(ship_tags) |> Enum.join(", ")}")

    Enum.each(ship_tags, fn {name, tag} ->
      enc = encrypted_region(tag)
      if byte_size(enc) > @iv_size do
        iv = binary_part(enc, 0, @iv_size)
        ct = binary_part(enc, @iv_size, byte_size(enc) - @iv_size)
        IO.puts("  #{name}: IV=#{Base.encode16(iv)}  ct=#{byte_size(ct)} bytes")

        expected_ks = Map.get(@ship_keystream, name)
        if expected_ks do
          IO.puts("    Verifying ciphertext matches known keystream constraints...")
          Enum.each(expected_ks, fn {pt_off, expected_ks_byte} ->
            if pt_off < byte_size(ct) do
              ct_byte = :binary.at(ct, pt_off)
              pt_byte = Map.get(@known_pt_bytes, pt_off)
              derived_ks = Bitwise.bxor(ct_byte, pt_byte)
              status = if derived_ks == expected_ks_byte, do: "OK", else: "MISMATCH"
              IO.puts("    offset #{pt_off}: ct=#{hex8(ct_byte)} XOR pt=#{hex8(pt_byte)} = ks=#{hex8(derived_ks)} (expected #{hex8(expected_ks_byte)}) #{status}")
            end
          end)
        end
      end
    end)
  end

  defp verify_known_keystream_standalone do
    IO.puts("  Known plaintext offsets: #{Map.keys(@known_pt_bytes) |> Enum.sort() |> Enum.join(", ")}")
    IO.puts("  Ship tags with keystream: #{Map.keys(@ship_keystream) |> Enum.join(", ")}")
    IO.puts("  Total keystream constraints: #{map_size(@known_pt_bytes) * map_size(@ship_keystream)} (#{map_size(@known_pt_bytes)} bytes x #{map_size(@ship_keystream)} tags)")
    IO.puts("  = 320 bits of constraint on the 128-bit key (massively over-determined)")
  end

  # ---- Extended Known Plaintext (all tag types) ----

  @doc """
  Derive known plaintext bytes for a tag based on its validated structural model.
  Returns a map of %{plaintext_offset => known_byte_value} or nil if layout unknown.
  """
  def known_bytes_for_tag(tag) do
    label = tag_label(tag) |> String.downcase()
    layout_key = find_layout_key(label)

    case layout_key && Map.get(@tag_layouts, layout_key) do
      nil -> nil
      layout ->
        Enum.flat_map(layout.records, fn {record_type, start_off, _size} ->
          struct_map = case record_type do
            :timer  -> @timer_struct
            :button -> @button_struct
            _       -> %{}
          end
          Enum.map(struct_map, fn {rel_off, value} -> {start_off + rel_off, value} end)
        end)
        |> Map.new()
    end
  end

  defp find_layout_key(label) do
    Enum.find_value(@tag_layout_map, fn {pattern, key} ->
      if String.contains?(label, pattern), do: key
    end)
  end

  @doc """
  Derive keystream constraint bytes for a tag from its structural known plaintext.
  Returns %{plaintext_offset => keystream_byte} or nil if layout unknown.
  """
  def derive_keystream(tag) do
    known = known_bytes_for_tag(tag)
    if known == nil or map_size(known) == 0 do
      nil
    else
      enc = encrypted_region(tag)
      if byte_size(enc) <= @iv_size do
        nil
      else
        ct = binary_part(enc, @iv_size, byte_size(enc) - @iv_size)
        known
        |> Enum.filter(fn {off, _} -> off < byte_size(ct) end)
        |> Enum.map(fn {off, pt_byte} ->
          ct_byte = :binary.at(ct, off)
          {off, Bitwise.bxor(ct_byte, pt_byte)}
        end)
        |> Map.new()
      end
    end
  end

  @doc """
  Run extended known plaintext analysis on all tags with validated structure models.
  Derives keystream bytes from structural constants (timer/button sub-record headers)
  and reports the total constraint set.

  Run: mix run -e "GrainExperiments.run_extended_known_plaintext()"
  """
  def run_extended_known_plaintext(tags \\ nil) do
    tags = tags || (load_all_tags(resolve_data_dir()) |> unique_tags())

    all_constraints =
      tags
      |> Enum.reject(&skip_tag?/1)
      |> Enum.flat_map(fn tag ->
        label = tag_label(tag)
        ks = derive_keystream(tag)
        if ks != nil and map_size(ks) > 0 do
          [{label, tag, ks}]
        else
          []
        end
      end)

    ship_names = ["x-wing", "tie", "falcon", "a-wing"]
    {ship_entries, nonship_entries} =
      Enum.split_with(all_constraints, fn {label, _, _} ->
        lbl = String.downcase(label)
        Enum.any?(ship_names, &String.contains?(lbl, &1))
      end)

    IO.puts("  Tags with validated structural model:")
    IO.puts("    Ship tags:     #{length(ship_entries)} (already verified)")
    IO.puts("    Non-ship tags: #{length(nonship_entries)} (NEW)")

    total_new_bytes = Enum.reduce(nonship_entries, 0, fn {_, _, ks}, acc -> acc + map_size(ks) end)
    total_ship_bytes = length(ship_entries) * 10

    IO.puts("\n  Derived keystream constraints:")

    Enum.each(nonship_entries, fn {label, tag, ks} ->
      enc = encrypted_region(tag)
      iv = if byte_size(enc) > @iv_size, do: binary_part(enc, 0, @iv_size), else: <<>>
      layout_key = find_layout_key(String.downcase(label))
      ct_size = byte_size(enc) - @iv_size

      iv_short = Base.encode16(binary_part(iv, 0, min(6, byte_size(iv))))
      IO.puts("    #{label} (#{layout_key}, ct=#{ct_size}B, IV=#{iv_short}...)")

      ks
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.each(fn {off, ks_byte} ->
        known_pt = known_bytes_for_tag(tag)
        pt_byte = Map.get(known_pt, off, 0)
        ct_byte = if off < ct_size do
          ct = binary_part(enc, @iv_size, byte_size(enc) - @iv_size)
          :binary.at(ct, off)
        else 0 end
        IO.puts("      offset #{String.pad_leading("#{off}", 3)}: ct=#{hex8(ct_byte)} XOR pt=#{hex8(pt_byte)} = ks=#{hex8(ks_byte)}")
      end)
    end)

    total_bytes = total_ship_bytes + total_new_bytes
    total_tags = length(ship_entries) + length(nonship_entries)

    IO.puts("\n  Summary:")
    IO.puts("    Ship tags:     #{length(ship_entries)} tags × 10 known bytes = #{total_ship_bytes} keystream bytes")
    IO.puts("    Non-ship tags: #{length(nonship_entries)} tags × ~#{if length(nonship_entries) > 0, do: div(total_new_bytes, max(length(nonship_entries), 1)), else: 0} known bytes = #{total_new_bytes} keystream bytes")
    IO.puts("    Total:         #{total_tags} tags, #{total_bytes} keystream bytes = #{total_bytes * 8} bits of constraint")
    IO.puts("    (was: 30 bytes / 240 bits from 3 ship tags)")
  end

  @doc """
  Verify a candidate 16-byte key against all known keystream constraints.
  Returns :ok if the key matches ALL 40 keystream bytes, or {:error, mismatches}
  with the count of failures.

      GrainExperiments.verify_key(<<key::binary-16>>, tags)
  """
  def verify_key(<<key::binary-size(16)>>, ship_tags) when is_map(ship_tags) do
    results =
      Enum.flat_map(ship_tags, fn {name, tag} ->
        enc = encrypted_region(tag)
        if byte_size(enc) <= @iv_size do
          []
        else
          iv = binary_part(enc, 0, @iv_size)
          ct = binary_part(enc, @iv_size, byte_size(enc) - @iv_size)
          ks = Grain128a.keystream(key, iv, byte_size(ct))

          expected = Map.get(@ship_keystream, name, %{})
          Enum.map(expected, fn {pt_off, expected_ks_byte} ->
            if pt_off < byte_size(ks) do
              actual_ks_byte = :binary.at(ks, pt_off)
              {name, pt_off, actual_ks_byte == expected_ks_byte}
            else
              {name, pt_off, false}
            end
          end)
        end
      end)

    mismatches = Enum.count(results, fn {_, _, ok} -> !ok end)
    if mismatches == 0, do: :ok, else: {:error, mismatches}
  end

  def verify_key(<<key::binary-size(16)>>, data_dir) when is_binary(data_dir) do
    tags = load_all_tags(data_dir) |> unique_tags()
    ship_tags = find_ship_tags(tags)
    verify_key(key, ship_tags)
  end

  # ---- Key Candidate Search ----

  defp search_key_candidates(tags) do
    ship_tags = find_ship_tags(tags)

    if map_size(ship_tags) == 0 do
      IO.puts("  No ship tags available for key verification")
      IO.puts("  Load X-Wing, TIE Fighter, Falcon, or A-Wing dumps to enable this")
      return()
    end

    IO.puts("  Using #{map_size(ship_tags)} ship tag(s) for key verification")

    candidates = build_key_candidates(tags)
    IO.puts("  Testing #{length(candidates)} candidate keys...")

    hits =
      Enum.filter(candidates, fn {label, key} ->
        case verify_key(key, ship_tags) do
          :ok ->
            IO.puts("\n  !!! KEY FOUND: #{label} = #{Base.encode16(key)} !!!\n")
            true
          {:error, n} when n <= 5 ->
            IO.puts("  near-miss: #{label} (#{n} mismatches)")
            false
          _ ->
            false
        end
      end)

    if hits == [] do
      IO.puts("  No key found among #{length(candidates)} candidates")
      IO.puts("  The key is in the DA000001-01 ASIC silicon — not derivable from tag data")
    end
  end

  defp build_key_candidates(tags) do
    candidates = [
      {"zeros", <<0::128>>},
      {"ones", <<0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8,
                 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8, 0xFF::8>>},
      {"LEGO_padded", pad16("LEGO")},
      {"SmartTag_padded", pad16("SmartTag")},
      {"SmartBrick_padded", pad16("SmartBrick")},
      {"DA000001_padded", pad16("DA000001")},
      {"EM9305_padded", pad16("EM9305")},
      {"EM4237_padded", pad16("EM4237")},
      {"P11_padded", pad16("P11")},
      {"sha256_LEGO", sha16("LEGO")},
      {"sha256_SmartTag", sha16("SmartTag")},
      {"sha256_SmartBrick", sha16("SmartBrick")},
      {"sha256_DA000001", sha16("DA000001")},
      {"sha256_EM4237", sha16("EM4237")},
      {"sha256_EM9305", sha16("EM9305")},
      {"sha256_P11", sha16("P11")},
      {"sha256_Bilbo", sha16("Bilbo")},
      {"sha256_Grain128A", sha16("Grain128A")},
      {"sha256_LEGOSmartPlay", sha16("LEGOSmartPlay")},
      {"sha256_010C", sha16(<<0x01, 0x0C>>)},
      {"sha256_identity_magic", sha16(<<0xD1, 0x4E, 0xE2, 0xA7>>)},
      {"sha256_item_magic", sha16(<<0x13, 0xA1, 0xBD, 0x0B>>)},
    ]

    tag_derived =
      tags
      |> Enum.flat_map(fn tag ->
        enc = encrypted_region(tag)
        if byte_size(enc) > @iv_size do
          iv = binary_part(enc, 0, @iv_size)
          [
            {"sha256_iv_#{tag_label(tag)}", sha16(iv)},
            {"sha256_enc_#{tag_label(tag)}", sha16(enc)},
          ]
        else
          []
        end
      end)

    fw_keys = load_firmware_candidate_keys()

    all = candidates ++ tag_derived ++ fw_keys
    all |> Enum.uniq_by(&elem(&1, 1))
  end

  defp load_firmware_candidate_keys do
    data_dir = resolve_data_dir()
    path = Path.join(data_dir, "candidate_keys.json")

    if File.exists?(path) do
      case File.read!(path) |> JSON.decode() do
        {:ok, data} ->
          ["universal_keys", "rkey_vicinity_keys", "top_entropy_keys", "special_candidates"]
          |> Enum.flat_map(fn section ->
            (data[section] || [])
            |> Enum.flat_map(fn
              %{"hex" => hex} when is_binary(hex) and byte_size(hex) == 32 ->
                case Base.decode16(String.upcase(hex), case: :mixed) do
                  {:ok, key} -> [{"fw_#{section}", key}]
                  _ -> []
                end
              _ -> []
            end)
          end)

        _ ->
          IO.puts("  Warning: could not parse #{path}")
          []
      end
    else
      []
    end
  end

  # ---- Ship Tag Matching ----

  defp find_ship_tags(tags) do
    ship_patterns = [
      {"x-wing", ~r/x.?wing/i},
      {"tie", ~r/tie/i},
      {"falcon", ~r/falcon|millennium/i},
      {"a-wing", ~r/a.?wing/i}
    ]

    Enum.reduce(ship_patterns, %{}, fn {name, pattern}, acc ->
      case Enum.find(tags, fn t -> Regex.match?(pattern, tag_label(t)) end) do
        nil -> acc
        tag -> Map.put(acc, name, tag)
      end
    end)
  end

  # ---- Tag Data Helpers (shared with NfcDecrypt) ----

  defp resolve_data_dir do
    cwd = File.cwd!()
    if String.ends_with?(cwd, "mac_capture"), do: Path.expand("../data", cwd), else: Path.join(cwd, "data")
  end

  defp load_all_tags(data_dir) do
    Path.wildcard(Path.join(data_dir, "*.jsonl"))
    |> Enum.sort()
    |> Enum.flat_map(&load_tags/1)
    |> Enum.reject(&skip_tag?/1)
  end

  defp load_tags(path) do
    path
    |> File.stream!()
    |> Stream.map(&String.trim/1)
    |> Stream.reject(&(&1 == ""))
    |> Stream.map(fn line ->
      case JSON.decode(line) do
        {:ok, tag} when is_map(tag) -> tag
        _ -> nil
      end
    end)
    |> Stream.reject(&is_nil/1)
    |> Enum.to_list()
  end

  defp unique_tags(tags) do
    tags
    |> Enum.uniq_by(fn tag ->
      blocks = tag["blocks"] || []
      last = last_payload_block_index(blocks)
      Enum.take(blocks, last + 1)
    end)
  end

  defp skip_tag?(tag) do
    label = (tag["item"] || tag["uid"] || "") |> String.downcase()
    String.contains?(label, "[fail]") or String.contains?(label, "[red flash]")
  end

  defp tag_label(tag), do: tag["item"] || tag["uid"] || "?"

  defp full_payload(tag) do
    blocks = tag["blocks"] || []
    last = last_payload_block_index(blocks)
    plen = payload_length(tag)
    data = blocks_to_binary(Enum.take(blocks, last + 1))
    if plen && byte_size(data) > plen, do: binary_part(data, 0, plen), else: data
  end

  defp encrypted_region(tag) do
    full = full_payload(tag)
    plen = payload_length(tag)

    if plen == nil or plen <= @cleartext_header_size do
      <<>>
    else
      enc_len = plen - @cleartext_header_size
      start = @cleartext_header_size
      if byte_size(full) > start do
        binary_part(full, start, min(enc_len, byte_size(full) - start))
      else
        <<>>
      end
    end
  end

  defp payload_length(tag) do
    case tag["blocks"] do
      [hex | _] when is_binary(hex) ->
        hex = String.pad_trailing(String.upcase(String.trim(hex)), 8, "0")
        case Base.decode16(hex, case: :mixed) do
          {:ok, <<hi::8, lo::8, _::binary>>} -> hi * 256 + lo
          _ -> nil
        end
      _ -> nil
    end
  end

  defp last_payload_block_index(blocks) do
    last_nonzero =
      blocks
      |> Enum.with_index()
      |> Enum.reject(fn {b, _} -> b in ["00000000", "0001"] end)
      |> List.last()
      |> case do
        {_, i} -> i
        nil -> 0
      end

    case payload_length_from_blocks(blocks) do
      nil -> last_nonzero
      plen ->
        n_blocks = div(plen + 3, 4)
        min(n_blocks, max(last_nonzero, 0))
    end
  end

  defp payload_length_from_blocks([hex | _]) when is_binary(hex) do
    hex = String.pad_trailing(String.upcase(String.trim(hex)), 8, "0")
    case Base.decode16(hex, case: :mixed) do
      {:ok, <<hi::8, lo::8, _::binary>>} -> hi * 256 + lo
      _ -> nil
    end
  end
  defp payload_length_from_blocks(_), do: nil

  defp blocks_to_binary(blocks) do
    blocks
    |> Enum.map(fn hex ->
      hex = String.upcase(String.trim(hex))
      hex = if rem(byte_size(hex), 2) == 1, do: hex <> "0", else: hex
      Base.decode16!(hex, case: :mixed)
    end)
    |> IO.iodata_to_binary()
  end

  # ---- Utility ----

  defp pad16(str) when is_binary(str) do
    bin = str
    pad_len = max(0, 16 - byte_size(bin))
    binary_part(bin <> :binary.copy(<<0>>, pad_len), 0, 16)
  end

  defp sha16(data) when is_binary(data) do
    :crypto.hash(:sha256, data) |> binary_part(0, 16)
  end

  defp hex8(byte), do: byte |> Integer.to_string(16) |> String.pad_leading(2, "0")

  defp find_expected_pt_size(label, ct_bytes) do
    match =
      Enum.find(@tag_pt_sizes, fn {name, _} ->
        String.contains?(String.downcase(label), String.downcase(name))
      end)

    case match do
      {_name, expected_pt} ->
        mac_bytes = ct_bytes - expected_pt
        if mac_bytes >= 0,
          do: "  (expected_pt=#{expected_pt}, implied_mac=#{mac_bytes})",
          else: "  (expected_pt=#{expected_pt}, SHORT by #{-mac_bytes})"
      nil -> ""
    end
  end

  defp leading_zeros(<<0, rest::binary>>), do: 1 + leading_zeros(rest)
  defp leading_zeros(_), do: 0

  defp byte_entropy(data) when byte_size(data) == 0, do: 0.0
  defp byte_entropy(data) do
    n = byte_size(data)
    freqs =
      :binary.bin_to_list(data)
      |> Enum.frequencies()
      |> Map.values()

    Enum.reduce(freqs, 0.0, fn count, acc ->
      p = count / n
      acc - p * :math.log2(p)
    end)
  end

  @doc """
  Export keystream constraints for the C attack tool (sparse format).
  Includes ALL tags with validated structural models, not just ships.

  Format: one line per tag, space-separated:
    IV_HEX offset1:ks_byte1 offset2:ks_byte2 ...
  Only known keystream positions are included (no zero-fill).

  Usage: mix run -e "GrainExperiments.export_constraints_c()"
  """
  def export_constraints_c(data_dir \\ nil) do
    data_dir = data_dir || resolve_data_dir()
    tags = load_all_tags(data_dir) |> unique_tags()

    # Collect all tags with known keystream bytes (ships use pre-verified @ship_keystream,
    # all others use structural derivation)
    ship_tags = find_ship_tags(tags)

    entries =
      tags
      |> Enum.reject(&skip_tag?/1)
      |> Enum.flat_map(fn tag ->
        enc = encrypted_region(tag)
        if byte_size(enc) <= @iv_size, do: [], else: do_export_entry(tag, enc, ship_tags)
      end)

    if entries == [] do
      IO.puts("No tags with known keystream found — cannot export constraints")
      return()
    end

    out_path = Path.join(Path.expand("..", data_dir), "crypto_attack/constraints.txt")
    File.write!(out_path, Enum.join(entries, "\n") <> "\n")
    IO.puts("Exported #{length(entries)} constraints (sparse) to #{out_path}")
  end

  defp do_export_entry(tag, enc, ship_tags) do
    iv = binary_part(enc, 0, @iv_size)
    iv_hex = Base.encode16(iv)

    # Check if this is a ship tag with pre-verified keystream
    ship_match = Enum.find(ship_tags, fn {name, st} ->
      encrypted_region(st) == enc and Map.has_key?(@ship_keystream, name)
    end)

    ks_map = case ship_match do
      {name, _} -> Map.get(@ship_keystream, name)
      nil -> derive_keystream(tag)
    end

    if ks_map != nil and map_size(ks_map) > 0 do
      pairs =
        ks_map
        |> Enum.sort_by(&elem(&1, 0))
        |> Enum.map(fn {off, ks_byte} -> "#{off}:#{hex8(ks_byte)}" end)
        |> Enum.join(" ")
      ["# #{tag_label(tag)}\n#{iv_hex} #{pairs}"]
    else
      []
    end
  end

  defp return, do: :ok
end
