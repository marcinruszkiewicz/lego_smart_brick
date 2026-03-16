# Cloning LEGO Smart Brick NFC Tags

## Why cloning works

LEGO smart tags use EM4233 chips (ISO 15693 / NFC Type 5). Key properties that make cloning viable:

1. **Open read access** — no authentication needed to read all data blocks.
2. **Identical payloads** — all tags of the same type (e.g. all Vader minifigures) contain byte-identical data regardless of their UID. The smart brick reads the encrypted data content, not the UID.
3. **Standard protocol** — ISO 15693 WRITE SINGLE BLOCK (0x21) works on any unlocked EM4233-compatible tag.

The original factory tags are permanently write-locked, but blank writable tags accept the same data and should function identically.

### UID and chip vendor independence

The smart brick identifies tags by the **stored block data** (encrypted payload), not by the UID. Cloning the same tag dump onto multiple blank stickers with different UIDs produces identical behaviour on the brick. Verified with Tie Fighter clones on blanks with UIDs `E0040150B81E7E2E` and `E0040150B81E7EA6` — both behave the same as the original LEGO tag (UID prefix `E016`, EM4233). Identity tags work the same way: an Emperor Palpatine dump cloned onto a new sticker (UID `E0040109049DE218`) has been verified working on the brick. Blanks from other chip vendors (e.g. UID prefix `E004`) work as long as they are ISO 15693 writable; the brick does not require the same IC as the originals.

## Compatible blank tags

You need **ISO 15693 / NFC Type 5** writable tag stickers. Specifically:

- **EM4233** (ideal — same chip as the originals)
- **ICODE SLIX / SLIX2** (NXP, also ISO 15693 compatible)
- Any ISO 15693 tag with enough writable EEPROM for the tag you want to clone (see below)

**Smaller stickers (e.g. 112 bytes = 28 blocks):** Tags that use ≤ 28 blocks total (block 0 header + payload) fit on 112-byte stickers. In the current dump set that is **R2-D2** (20 blocks), **Tie Fighter** (28 blocks), **X-Wing** (28 blocks), **Falcon** (28 blocks), **Hyperdrive** (28 blocks), and **Fuel cargo** (26 blocks). Larger tags (Vader, Lightsaber, Han, Chewbacca, C-3PO, etc.) need more blocks and will not fit. Clone only tags that fit within your sticker’s block count.

**Full-size (264+ bytes):** For all saved tags you need at least 66 blocks × 4 bytes (264 bytes) of writable EEPROM.

Look for "ISO 15693 NFC sticker" or "ICODE SLIX sticker" or "NFC Type 5 sticker" when purchasing. Standard NFC stickers (NTAG213/215/216) will **not** work — those are ISO 14443 (Type 2), a completely different protocol.

## Available tags to clone

All saved tag dumps in `data/` are available. The clone tool loads every `.jsonl` file, deduplicates by payload, and shows a single menu entry per unique tag. The file `data/nfc_dump_2026-03-16.jsonl` contains verified clones (e.g. Palpatine sticker clone) written to new stickers and confirmed working. As of the latest captures:

| # | Item | Type | Data blocks | Payload bytes |
|---|------|------|-------------|---------------|
| 1 | Darth Vader | Identity (minifigure) | 43 | 169 |
| 2 | Emperor Palpatine | Identity (minifigure) | 43 | 171 |
| 3 | Leia | Identity (minifigure) | 40 | 158 |
| 4 | Luke Skywalker (Pilot / Falcon) | Identity (minifigure) | 40 | 157 |
| 5 | Han Solo | Identity (minifigure) | 29 | 113 |
| 6 | Chewbacca | Identity (minifigure) | 30 | 116 |
| 7 | C-3PO | Identity (minifigure) | 30 | 118 |
| 8 | R2-D2 | Identity (tile) | 19 | 74 |
| 9 | Lightsaber Tile | Item (tile) | 32 | 126 |
| 10 | Tie Fighter | Item (tile) | 27 | 107 |
| 11 | X-Wing Tile | Item (tile) | 27 | 107 |
| 12 | Falcon (Millennium Falcon) | Item (tile) | 27 | 107 |
| 13 | Hyperdrive | Item (tile) | 28 | 109 |
| 14 | Fuel cargo | Item (tile) | 26 | 101 |

Identity = minifigure/character tag. Item = vehicle/object tile.

**Millennium Falcon set:** Tags from the Falcon set (Luke, Han, Chewbacca, C-3PO, Lightsaber, Falcon ship tile, Hyperdrive, Fuel cargo) are in `data/nfc_dump_2026-03-12.jsonl`. Luke from the Falcon set uses the same payload as Pilot Luke, so both appear as one option in the clone menu. The smaller tiles (Falcon, Hyperdrive, Fuel cargo) fit on 112-byte stickers (28 blocks); full-size identities need 66×4 bytes (264 bytes).

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

This is useful for experiments like truncating a tag to fit a smaller sticker or testing custom block 0 values.

**Practical rules when cloning:**
- When cloning to a **smaller sticker** (e.g. 28 blocks): keep the **original block 0** (including capacity `0x010C`). Do not rewrite capacity to the physical tag size — the brick rejects that. Only truncate the block list.
- **Wrong payload length** in block 0 (e.g. too small) can make the brick **flash red**; wrong but plausible length or invalid ciphertext usually causes the brick to **ignore** the tag (no flash). Truncating the encrypted payload (e.g. Lightsaber to 28 blocks with a fixed header) is not sufficient — the brick still ignores it; it likely validates the full ciphertext (e.g. MAC).
- For full details on header layout and validation behaviour, see [lego-smart-brick-nfc-comparison.md](lego-smart-brick-nfc-comparison.md).

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
