# Cloning LEGO Smart Brick NFC Tags

## Why cloning works

LEGO smart tags use EM4233 chips (ISO 15693 / NFC Type 5). Key properties that make cloning viable:

1. **Open read access** — no authentication needed to read all data blocks.
2. **Identical payloads** — all tags of the same type (e.g. all Vader minifigures) contain byte-identical data regardless of their UID. The smart brick reads the encrypted data content, not the UID.
3. **Standard protocol** — ISO 15693 WRITE SINGLE BLOCK (0x21) works on any unlocked EM4233-compatible tag.

The original factory tags are permanently write-locked, but blank writable tags accept the same data and should function identically.

### UID and chip vendor independence

The smart brick identifies tags by the **stored block data** (encrypted payload), not by the UID. Cloning the same tag dump onto multiple blank stickers with different UIDs produces identical behaviour on the brick. Verified with Tie Fighter clones on blanks with UIDs `E0040150B81E7E2E` and `E0040150B81E7EA6` — both behave the same as the original LEGO tag (UID prefix `E016`, EM4233). Blanks from other chip vendors (e.g. UID prefix `E004`) work as long as they are ISO 15693 writable; the brick does not require the same IC as the originals.

## Compatible blank tags

You need **ISO 15693 / NFC Type 5** writable tag stickers. Specifically:

- **EM4233** (ideal — same chip as the originals)
- **ICODE SLIX / SLIX2** (NXP, also ISO 15693 compatible)
- Any ISO 15693 tag with enough writable EEPROM for the tag you want to clone (see below)

**Smaller stickers (e.g. 112 bytes = 28 blocks):** Tags that use ≤ 28 blocks total (block 0 header + payload) fit on 112-byte stickers. In the current dump set that is **R2-D2** (20 blocks), **Tie Fighter** (28 blocks), and **X-Wing** (28 blocks). Larger tags (Vader, Lightsaber, etc.) need more blocks and will not fit. Clone only tags that fit within your sticker’s block count.

**Full-size (264+ bytes):** For all saved tags you need at least 66 blocks × 4 bytes (264 bytes) of writable EEPROM.

Look for "ISO 15693 NFC sticker" or "ICODE SLIX sticker" or "NFC Type 5 sticker" when purchasing. Standard NFC stickers (NTAG213/215/216) will **not** work — those are ISO 14443 (Type 2), a completely different protocol.

## Available tags to clone

All saved tag dumps in `data/` are available. As of the last capture:

| # | Item | Type | Data blocks | Payload bytes |
|---|------|------|-------------|---------------|
| 1 | Darth Vader | Identity (minifigure) | 43 | 169 |
| 2 | Emperor Palpatine | Identity (minifigure) | 43 | 171 |
| 3 | Leia | Identity (minifigure) | 40 | 158 |
| 4 | Lightsaber Tile | Item (tile) | 32 | 126 |
| 5 | Pilot Luke Skywalker | Identity (minifigure) | 40 | 157 |
| 6 | R2-D2 | Identity (tile) | 19 | 74 |
| 7 | Tie Fighter | Item (tile) | 27 | 107 |
| 8 | X-Wing Tile | Item (tile) | 27 | 107 |

Identity = minifigure/character tag. Item = vehicle/weapon tile.

## How to clone

### Prerequisites

- ESP32 (Wemos D1 R32) with PN7150 shield, flashed with `nfc_tool.ino`
- Blank ISO 15693 tag sticker
- Mac with Elixir 1.18+

### Steps

1. **Flash the Arduino** with the latest `nfc_tool/nfc_tool.ino` (includes write support).

2. **Close Arduino Serial Monitor** (it locks the port).

3. **Run the clone tool:**
   ```bash
   cd mac_capture
   mix run -e "NfcClone.run()"
   ```

4. **Pick a tag** from the numbered menu.

5. **Place a blank tag sticker** on the PN7150 reader when prompted.

6. **Watch the progress bar** — each block is written and then read back to verify.

7. **Done** — the tool reports how many blocks succeeded/failed.

## Custom experiments (NfcCustomClone)

For low-level experiments, `mac_capture` also includes an **experimental** custom clone tool:

- `NfcCustomClone` can load a saved tag, truncate it to a target sticker size (e.g. 28 blocks for a 112-byte sticker), and rewrite **block 0** so the header’s payload length and capacity match what will actually be written.
- It can also apply arbitrary block 0 hex or send a fully custom `CLONE:<hex>` payload.

Run it from the `mac_capture` directory:

```bash
mix run -e "NfcCustomClone.run()"
```

This is useful for experiments like **Lightsaber on a 112-byte sticker**: truncate the tag to 28 blocks, fix the header to the new payload length and capacity, and see whether the smart brick starts recognizing the truncated tag (testing how strictly it validates the header fields).

**Result (Lightsaber truncate + fix header):** A truncated Lightsaber (28 blocks) with block 0 rewritten to payload length 108 and capacity 112 was written successfully to a blank sticker. The smart brick **still did not recognize** the tag (same “does nothing” behaviour as the earlier partial write). So fixing the header to match the written data is not sufficient. The brick likely validates the **encrypted payload** (e.g. AES-CCM MAC over the full ciphertext) or expects the full payload; truncating the ciphertext leaves it invalid, so the tag is ignored.

**Capacity field (bytes 2–3 of block 0):** On a 112-byte sticker, writing X-Wing with **modified** block 0 (payload 107, capacity 112 = `006B0070`) was **not** recognized by the brick; a **straight copy** (same 28 blocks but capacity left as 268 = `006B010C`) **was** recognized. So the brick appears to **require capacity 0x010C (268)** in the header; changing it to the physical tag size breaks recognition. When cloning tags that fit in 28 blocks to a 112-byte sticker, keep the original block 0 (including 0x010C) and only truncate the block list — do not rewrite capacity to 112. The custom-clone "truncate to sticker" experiment now keeps the original capacity for this reason.

**Payload length (bytes 0–1 of block 0):** A clean test with X-Wing payload and block 0 set to `0000010C` (payload length 0, capacity 268), written to a fully zero-padded 28-block sticker, was **not** recognized by the brick. So the brick **requires a proper (non-zero) payload length** in the header; it does not accept 0. **Wrong non-zero value:** With block 0 set to `000F010C` (payload length 15 instead of 107), the brick **flashed red continuously** — a distinct error indication it never showed for other invalid tags (which it simply ignored). So the brick appears to validate bytes 0–1 and signal an error when the value is wrong but non-zero (e.g. it may read that many bytes then fail decryption/MAC or structure checks). **Payload length vs content ID:** X-Wing and Tie Fighter both have 0x006B (107) in bytes 0–1; they also both have 107-byte payloads, which fits the payload-length interpretation. If bytes 0–1 were a content/type ID (as sometimes guessed elsewhere), two different items would likely have different IDs; the fact that two different tiles share 0x006B is consistent with length (same payload size) and would be a coincidence if it were an ID. So the payload-length interpretation remains the best fit.

### Further experiment ideas (NfcCustomClone)

All of these use experiment **3** (custom block 0) or **4** (raw hex); pad to 28 blocks when prompted so the sticker is fully overwritten and reusable.

- **Payload length off-by-one:** X-Wing (107 bytes payload). Try block 0 `006A010C` (106) and `006C010C` (108). **Result:** Both 106 and 108 are ignored (no red flash); exact length 107 is required for recognition. Only a very wrong value (e.g. 15) caused red flash.
- **Capacity near-miss:** Keep X-Wing payload and 107 length; try bytes 2–3 = `010B` or `010D` (268±1). **Result:** Both are ignored (no red flash); capacity must be exactly 0x010C (268) for recognition.
- **Single-byte flip in ciphertext:** Use experiment **5** (flip one bit in a payload block): pick a tag (e.g. X-Wing), choose block index (default 5), byte 0–3 and bit 0–7 to flip. The tool writes the modified dump so you can test whether the brick ignores (MAC fail) or red-flashes. No need to paste raw hex. **Result:** One bit flipped in a payload block (e.g. block 3, byte 0) → brick **ignores** the tag (no red flash). So MAC (or integrity) failure is silent, unlike a wrong header value which can trigger red flash.
- **Swap headers between tag types:** Write Tie Fighter payload (blocks 1–28) with Vader’s block 0 (`00A9010C`, length 169). Brick would try to read 169 bytes from a 28-block tag (only 108 bytes). **Result:** Tag is **ignored** (no red flash). Declared length 169 with only 108 bytes of payload is treated like other invalid payloads (silent ignore).
- **Maximum payload length value:** Block 0 `FFFF010C` (65535) with 28 blocks (108 bytes). **Result:** Tag is **ignored** (no red flash). So an absurd length value is treated like other invalid payloads, not a distinct error.
- **R2-D2 with wrong length:** R2-D2 has 74-byte payload (`004A010C`). Try 73 or 75. **Result:** 75 (`004B010C`) is **ignored** (no red flash), same as X-Wing off-by-one.

### What happens under the hood

1. The Elixir app loads all `.jsonl` files from `data/`, deduplicates by payload content, and shows a menu.
2. When you pick a tag, it strips trailing zero/filler blocks and sends `CLONE:<hex>\n` over serial.
3. The Arduino parses the hex, enters clone mode, and waits for a tag.
4. On tag detect, it writes each 4-byte block using ISO 15693 WRITE SINGLE BLOCK (0x21).
5. After each write, it reads the block back and compares — reporting `WRITE_OK` or `WRITE_FAIL` with expected vs actual bytes.
6. A final `WRITE_DONE:ok/total` summary is sent back.

## Serial protocol

Commands sent from Mac to Arduino:

| Command | Description |
|---------|-------------|
| `CLONE:<hex>\n` | Load block data and enter clone mode. `<hex>` is concatenated 4-byte blocks as hex (e.g. `00A9010C012A7206...`). |
| `READ\n` | Switch back to normal read mode. |
| `CANCEL\n` | Cancel pending clone, return to read mode. |

Responses from Arduino to Mac:

| Response | Description |
|----------|-------------|
| `CLONE_READY:<n> blocks loaded...` | Clone data accepted, waiting for tag. |
| `CLONE_ERR:<message>` | Invalid clone data. |
| `WRITE_START:<n>` | Beginning write of n blocks. |
| `WRITE_OK:<block>` | Block written and verified. |
| `WRITE_FAIL:<block> expected=<hex> got=<hex>` | Block write/verify failed. |
| `WRITE_DONE:<ok>/<total>` | Clone complete. |

## Troubleshooting

**All blocks fail with WRITE_FAIL:**
- The tag may be write-locked (factory LEGO tags are permanently locked). Use a blank, unlocked tag.
- Some tags require the OPTION flag (0x40) in the write command. If you see consistent failures on a known-writable tag, this may need adjustment in the Arduino sketch.

**Timed out waiting for CLONE_READY:**
- Remove any tag from the reader before choosing a tag to clone. The Arduino only processes the `CLONE:` command when it reaches the start of its loop; if it’s busy reading a tag or waiting for tag removal, the command is delayed and the Mac may time out. After sending the command, the tool will prompt you to present a blank tag.

**Port busy error:**
- Close Arduino Serial Monitor before running the clone tool. Only one application can use the serial port at a time.

**Tag not detected:**
- Ensure the tag is ISO 15693 (Type 5). NFC Type 2 tags (NTAG21x) won't be detected.
- Hold the tag steady on the reader for 1-2 seconds.

**Partial write (some blocks OK, some fail):**
- The tag may have insufficient memory. Ensure it has at least as many blocks as the source tag (e.g. on a 112-byte sticker only R2-D2, Tie Fighter, and X-Wing fit).
- If you clone a tag that doesn’t fit (e.g. Lightsaber to a 28-block sticker), the brick **does nothing** — it ignores the tag entirely (no error, no crash). Use a sticker with enough blocks or pick a smaller tag.
- Some blocks on partially-written tags may be one-time-programmable. Use a fresh tag for the next clone.

## Adding new tags

To add more tags to the clone library, scan them with the capture tool first:

```bash
mix run -e "NfcCapture.run()"
```

Label each tag when prompted. The dump is saved to `data/nfc_dump_YYYY-MM-DD.jsonl` and will automatically appear in the clone menu next time.
