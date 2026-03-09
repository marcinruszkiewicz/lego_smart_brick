# Cloning LEGO Smart Brick NFC Tags

## Why cloning works

LEGO smart tags use EM4233 chips (ISO 15693 / NFC Type 5). Key properties that make cloning viable:

1. **Open read access** — no authentication needed to read all data blocks.
2. **Identical payloads** — all tags of the same type (e.g. all Vader minifigures) contain byte-identical data regardless of their UID. The smart brick reads the encrypted data content, not the UID.
3. **Standard protocol** — ISO 15693 WRITE SINGLE BLOCK (0x21) works on any unlocked EM4233-compatible tag.

The original factory tags are permanently write-locked, but blank writable tags accept the same data and should function identically.

## Compatible blank tags

You need **ISO 15693 / NFC Type 5** writable tag stickers. Specifically:

- **EM4233** (ideal — same chip as the originals)
- **ICODE SLIX / SLIX2** (NXP, also ISO 15693 compatible)
- Any ISO 15693 tag with at least 66 blocks × 4 bytes (264 bytes) of writable EEPROM

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

**Port busy error:**
- Close Arduino Serial Monitor before running the clone tool. Only one application can use the serial port at a time.

**Tag not detected:**
- Ensure the tag is ISO 15693 (Type 5). NFC Type 2 tags (NTAG21x) won't be detected.
- Hold the tag steady on the reader for 1-2 seconds.

**Partial write (some blocks OK, some fail):**
- The tag may have insufficient memory. Ensure it has at least as many blocks as the source tag.
- Some blocks on partially-written tags may be one-time-programmable. Use a fresh tag.

## Adding new tags

To add more tags to the clone library, scan them with the capture tool first:

```bash
mix run -e "NfcCapture.run()"
```

Label each tag when prompted. The dump is saved to `data/nfc_dump_YYYY-MM-DD.jsonl` and will automatically appear in the clone menu next time.
