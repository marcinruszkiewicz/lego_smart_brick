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


| Field            | Value                                                                                           |
| ---------------- | ----------------------------------------------------------------------------------------------- |
| **Manufacturer** | EM Microelectronic (code 0x16)                                                                  |
| **IC reference** | 0x17 → custom LEGO die (matches EM4237 with Grain-128A; **not** EM4233SLIC=0x02 or EM4233=0x09) |
| **Memory**       | 66 blocks × 4 bytes = 264 bytes                                                                 |
| **Security**     | All blocks permanently write-locked (0x01)                                                      |
| **Read access**  | Open (no authentication required)                                                               |


The tag chip is **NOT NXP** — it's made by **EM Microelectronic**. IC reference 0x17 matches the **EM4237**, which implements **Grain-128A** (ISO/IEC 29167-13) encryption. It is not an off-the-shelf EM4233 (IC ref 0x09) or EM4233SLIC (IC ref 0x02). The payload data is read-open (no authentication required).

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
  - **Validation:** Wrong but non-zero (e.g. `000F010C`, length 15) causes the brick to **flash red continuously** (error), unlike invalid/ignored tags. Length 0 → no reaction. So the brick uses bytes 0–1 and signals when they are wrong. X-Wing and Tie Fighter both have 0x006B (107); both have 107-byte payloads, so this fits “payload length”. If it were a content/type ID, two different items sharing the same value would be a coincidence; as length it is not.
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

So the header layout is **confirmed**: `[payload_len_hi, payload_len_lo, 0x01, 0x0C]` — i.e. block 0 is **length (bytes 0–1) / total capacity (bytes 2–3)**.

### Block 1 (first payload block) — format byte 0x01

The **first byte of block 1** is always `**0x01`** in every known tag. If that byte were part of the ciphertext, it would vary per tag (ciphertext is effectively random). So it is **not** encrypted — it is a cleartext **format/version byte**. The remaining 3 bytes of block 1 are the start of the per-content IV (12 bytes total at bytes 5-16), followed by Grain-128A ciphertext. So block 1 = **format byte `01` (cleartext) + first 3 bytes of IV**.

**Format-byte experiments** (NfcCustomClone → experiment 6): Change the first byte of block 1 and write to a blank; note whether the brick recognizes, ignores, or red-flashes.


| Format byte                                          | Result                                           |
| ---------------------------------------------------- | ------------------------------------------------ |
| `0x01` (original)                                    | Recognized.                                      |
| `0x02` (Hyperdrive, block 1 `01391E39` → `02391E39`) | **Ignored** — brick does nothing (no red flash). |
| `0x00` (Hyperdrive, block 1 → `00391E39`)            | **Ignored.**                                     |
| `0xFF` (Hyperdrive, block 1 → `FF391E39`)            | **Ignored.**                                     |


So the brick requires the format byte to be exactly `0x01`; any other value (0x00, 0x02, 0xFF) is treated like other invalid payloads (silent ignore, no red flash).

### Header and payload validation (from clone experiments)

Experiments with `NfcCustomClone` (modified block 0 or payload) show how the brick reacts:

- **Capacity (bytes 2–3 of block 0):** Must be exactly **0x010C** (268). X-Wing with capacity 112 (`006B0070`) was rejected; same 28 blocks with original capacity 268 (`006B010C`) was accepted. So the brick requires the fixed capacity value; changing it to the physical tag size breaks recognition.
- **Payload length (bytes 0–1):** Must be non-zero and **exact**. Length 0 → tag ignored. Wrong but non-zero (e.g. 15 instead of 107) → brick **flashes red continuously** (distinct error). Off-by-one (106 or 108 instead of 107) → tag ignored (no red flash). So bytes 0–1 are interpreted as payload length; only a “very wrong” value triggers red flash.
- **Payload length vs content ID:** X-Wing and Tie Fighter both have 0x006B (107) and 107-byte payloads; if bytes 0–1 were a content/type ID, two different items sharing the same value would be a coincidence — so the payload-length interpretation fits.
- **Truncated payload:** Lightsaber truncated to 28 blocks with block 0 rewritten to match (payload 108, capacity 112) was written successfully but the brick **did not recognize** the tag. So fixing the header is not sufficient; the ASIC likely validates ciphertext integrity (e.g. Grain-128A MAC or format check).
- **Single-byte flip in ciphertext:** One bit flipped in a payload block → brick **ignores** the tag (no red flash). So MAC (or integrity) failure is silent, unlike a wrong header value which can trigger red flash.
- **Swap headers:** Tie Fighter payload (28 blocks) with Vader’s block 0 (length 169) → ignored. Block 0 `FFFF010C` with 28 blocks → ignored. R2-D2 with length 75 instead of 74 → ignored.

## Data region (blocks 1–N)

- **Vader:** blocks 1–41 are unique data (41 blocks = 164 bytes).
- **Tie Fighter:** blocks 1–25 are unique data (25 blocks = 100 bytes).
- Content is **fully different** between different tags and same on the same types - even though different Luke/Vaders have different UUIDs the content is the same
- not NDEF, some kind of encoded data blob

## Zero region and filler

- After the last data block, both have a long run of `**00000000`** (unused / reserved).
- Then two 2-byte blocks `**0001`** — these are the **past-end filler** from the tag; we use them to stop reading.

## Encryption

The payload (blocks 1–N) is most likely encrypted with **Grain-128A** (ISO/IEC 29167-13), a lightweight stream cipher. Decryption is handled by the **DA000001-01 ASIC** on the smart brick — the EM9305 BLE SoC never sees encrypted tag data. The 128-bit key is in the ASIC silicon, not in the firmware binary. (The AES-CCM functions in the EM9305 firmware are for BrickNet PAwR / ASIC mutual authentication.)

Critical finding: **two Vader tags with different UIDs have identical encrypted payloads**. This means the nonce is not UID-derived, the key is global, and all tags of the same type produce the same ciphertext. This makes byte-perfect cloning viable.

Full analysis: [encryption-analysis.md](encryption-analysis.md).

## Cloning implications

Since tag data is openly readable, identical across same-type tags, and not UID-bound, **byte-perfect cloning** to a blank writable ISO 15693 tag produces a tag the smart brick treats identically. The blank need not be the same chip (the LEGO tags use a custom EM die, not off-the-shelf EM4233); blanks with different UIDs or vendors work. Factory tags are write-locked; use blank stickers. For the practical workflow and which tags fit which sticker sizes, see [cloning-guide.md](cloning-guide.md).

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

