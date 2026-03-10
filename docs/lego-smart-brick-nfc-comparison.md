# LEGO Smart Brick NFC Tag Block Comparison

Comparison of two ISO 15693 (Type 5) dumps from the new LEGO smart brick system (not LEGO Dimensions).

## Tag summary


|                                | Vader minifigure | Tie Fighter      |
| ------------------------------ | ---------------- | ---------------- |
| **UID**                        | E0165C011FC66027 | E0165C01277878E9 |
| **AFI**                        | 00               | 00               |
| **DSFID**                      | 00               | 00               |
| **Data blocks** (before zeros) | 0–42 (43 blocks) | 0–26 (27 blocks) |
| **Total blocks**               | 66               | 66               |


## NFC Chip Identification (from GET SYSTEM INFORMATION)

| Field | Value |
| ----- | ----- |
| **Manufacturer** | EM Microelectronic (code 0x16) |
| **IC reference** | 0x17 → EM4233 (2k-bit EEPROM, 96-bit crypto engine) |
| **Memory** | 66 blocks × 4 bytes = 264 bytes |
| **Security** | All blocks permanently write-locked (0x01) |
| **Read access** | Open (no authentication required) |

The tag chip is **NOT NXP** — it's made by **EM Microelectronic**. The EM4233 has a built-in 96-bit secret key crypto engine for privacy mode and 32-bit password protection, but the payload data is read-open.

## UID

- Both UIDs start with **E0165C01** — `E0` = ISO 15693, `16` = EM Microelectronic manufacturer code, `5C01` = product code.
- The remaining 4 bytes are unique per tag: **1FC66027** vs **277878E9**.
- Yoda minifigure has  **1BC9BA8D** in UID

**Clones on other chips:** The brick does not key off the UID. Cloning the same payload to blanks with different UIDs (e.g. `E0040150B81E7E2E`, `E0040150B81E7EA6`) produces identical behaviour; the brick uses the stored block data only. Blanks from other vendors (UID prefix e.g. `E004`) work as long as they are ISO 15693 writable.

## Block 0 (header)


| Tag         | Block 0    |
| ----------- | ---------- |
| Vader       | `00A9010C` |
| Tie Fighter | `006B010C` |


- **Bytes 2–3 (common): `010C`** — **0x010C = 268** = total tag size in bytes (67 × 4-byte blocks). So block 0 encodes the tag’s capacity.
- **Bytes 0–1 (per-tag): `00A9` / `006B`** — **Payload length in bytes**: 0xA9 = **169**, 0x6B = **107**.
  - Vader: 43 blocks of data = 172 bytes; 172 − 169 = **3 bytes padding** (e.g. the trailing `00 00 00` of the last data block `3F000000`).
  - Tie Fighter: 27 blocks = 108 bytes; 108 − 107 = **1 byte padding**.
- So block 0 is: **[payload_len_hi, payload_len_lo, total_size_hi, total_size_lo]** with total size fixed at 268 bytes and payload length varying; the rest is padding (`00000000` blocks and trailing bytes in the last data block).

### Confirmed with 11 tags from hardware.md

All tags in `data/hardware_md_tag_dumps.jsonl` and `data/nfc_dump_2026-03-07.jsonl` were checked:


| Item / type                  | Block 0    | Payload len (B0–B1 BE) | Bytes 2–3 |
| ---------------------------- | ---------- | ---------------------- | --------- |
| Pilot Luke (Identity)        | `009D010C` | 157                    | `010C` ✓  |
| Jedi Luke (Identity)         | `009D010C` | 157                    | `010C` ✓  |
| Darth Vader (Identity)       | `00A9010C` | 169                    | `010C` ✓  |
| Emperor Palpatine (Identity) | `00AB010C` | 171                    | `010C` ✓  |
| Leia (Identity)              | `009E010C` | 158                    | `010C` ✓  |
| R2-D2 (Identity, tile)       | `004A010C` | 74                     | `010C` ✓  |
| Lightsaber (Item)            | `007E010C` | 126                    | `010C` ✓  |
| Lightsaber clone (Item)      | `007E010C` | 126                    | `010C` ✓  |
| X-Wing (Item)                | `006B010C` | 107                    | `010C` ✓  |
| Vader minifigure (capture)   | `00A9010C` | 169                    | `010C` ✓  |
| Tie Fighter (capture)        | `006B010C` | 107                    | `010C` ✓  |


- **Bytes 2–3 = `010C`** holds for every tag. Total size 268 bytes is fixed.
- **Bytes 0–1 = payload length (big-endian)** holds: each tag’s last payload block ends with the correct number of padding zeros (1–3 bytes), and the preceding bytes match the declared length.
- **Last data block** is end-of-payload + zero padding to 4 bytes; no terminator sentinel. Use the header payload length to know how many bytes to take from the last block.

So the header layout is **confirmed**: `[payload_len_hi, payload_len_lo, 0x01, 0x0C]`.

## Data region (blocks 1–N)

- **Vader:** blocks 1–41 are unique data (41 blocks = 164 bytes).
- **Tie Fighter:** blocks 1–25 are unique data (25 blocks = 100 bytes).
- Content is **fully different** between different tags and same on the same types - even though different Luke/Vaders have different UUIDs the content is the same
- not NDEF, some kind of encoded data blob

## Zero region and filler

- After the last data block, both have a long run of `**00000000`** (unused / reserved).
- Then two 2-byte blocks `**0001`** — these are the **past-end filler** from the tag; we use them to stop reading.

## Encryption

The payload (blocks 1–N) is **AES-128-CCM encrypted**. Confirmed by firmware disassembly. The encryption key is stored in a hardware register on the smart brick MCU, not in the firmware binary.

Critical finding: **two Vader tags with different UIDs have identical encrypted payloads**. This means the nonce is not UID-derived, the key is global, and all tags of the same type produce the same ciphertext. This makes byte-perfect cloning viable.

Full analysis: [encryption-analysis.md](encryption-analysis.md).

## Cloning implications

Since tag data is openly readable, identical across same-type tags, and not UID-bound:

- **Byte-perfect cloning** to a blank writable ISO 15693 tag produces a tag the smart brick treats identically to the original. The blank need not be the same chip as LEGO (EM4233, `E016`); blanks with different UIDs or vendors (e.g. `E004`) work.
- The clone tool writes only the data blocks (stripping trailing zero filler and `0001` end markers).
- Factory tags are permanently write-locked, so you need blank writable stickers. Smaller stickers (e.g. 112 bytes = 28 blocks) work for tags that fit (R2-D2, Tie Fighter, X-Wing). If a tag is too large for the sticker (partial write), the brick ignores the tag entirely — no error, no crash.

See [cloning-guide.md](cloning-guide.md) for the practical workflow.

## Tools

- **Capture**: `mix run -e "NfcCapture.run()"` — read tags and save to `data/nfc_dump_YYYY-MM-DD.jsonl`.
- **Analyze**: `mix run -e "NfcAnalyze.run()"` — diff/compare tag dumps, check header layout.
- **Clone**: `mix run -e "NfcClone.run()"` — write a saved tag to a blank sticker.
- **Decrypt**: `mix run -e "NfcDecrypt.run()"` — attempt decryption with various ciphers and keys.

## Historical notes to “figure out how they work”

1. **Payload (blocks 1–N)** — Likely binary blob (ID, type, maybe crypto). Look for repeated byte patterns, or try XOR/diff between two tags of the same type.



## What we did with only two tags

- **Analysis script** (`mac_capture`): run `mix run -e "NfcAnalyze.run(\"nfc_dump_2026-03-07.jsonl\")"` to diff tags and print per-tag summary. Use `data/hardware_md_tag_dumps.jsonl` for the 9 HARDWARE.md tags.
- **Documented** the inferred layout and block counts in this file.
- **Confirmed** the header hypothesis with 11 tags

