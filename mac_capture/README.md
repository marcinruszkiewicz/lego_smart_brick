# mac_capture

Captures NFC ISO 15693 (Type 5) tag data from the Arduino **nfc_tool** sketch over USB serial and appends JSON lines to a timestamped file.

## Requirements

- Elixir 1.18+ (for built-in `JSON` module)
- Arduino running **nfc_tool** at 115200 baud

## Setup

```bash
cd mac_capture
mix deps.get
```

## Run

### Capture (read tags)

With auto-detected USB serial port (first port with `usbmodem` in the name):

```bash
mix run -e "NfcCapture.run()"
```

With an explicit port:

```bash
mix run -e "NfcCapture.run(port: \"/dev/cu.usbmodem14101\")"
```

Show Arduino debug lines (`[D] ...` / `[DEBUG] ...`) in the capture output (useful since the serial port is exclusive, so you can't also use Arduino Serial Monitor):

```bash
mix run -e "NfcCapture.run(debug: true)"
```

Output is written to `nfc_dump_YYYY-MM-DD.jsonl` in the `../data` directory. Each line is one JSON object: `uid`, `afi`, `dsfid`, `blocks`, `item`, `category` (identity/item/unknown). For older JSONL files missing `category`, run a backfill from the decrypt module: `mix run -e "NfcDecrypt.backfill_category_jsonl(\"../data\")"`.

Press **Ctrl+C** to stop.

### Clone (write a saved tag to a blank tag)

Clone mode loads saved dumps from `../data/*.jsonl`, shows a menu, then sends a `CLONE:<hex>` command to the Arduino and writes the blocks to a presented blank tag. Clones behave identically to the original even when the blank has a different UID or chip vendor (e.g. `E004`); the smart brick uses tag data, not UID. On 112-byte (28-block) stickers, only tags that fit in 28 blocks (e.g. R2-D2, Tie Fighter, X-Wing) can be cloned — see [../docs/cloning-guide.md](../docs/cloning-guide.md).

Run:

```bash
mix run -e "NfcClone.run()"
```

With an explicit port:

```bash
mix run -e "NfcClone.run(port: \"/dev/cu.wchusbserial1110\")"
```

Show Arduino debug lines during cloning:

```bash
mix run -e "NfcClone.run(debug: true)"
```

### Experimental: custom clone / header experiments

`NfcCustomClone` is an experimental tool for low-level clone experiments. It lets you:

- Pick a saved tag dump.
- Optionally truncate it to a given number of blocks (e.g. 28 for 112-byte stickers) and rewrite block 0 (payload length / capacity) accordingly.
- Apply custom block 0 hex.
- Or send a raw hex payload as `CLONE:<hex>`.

Run:

```bash
mix run -e "NfcCustomClone.run()"
```

This is intended for experiments like rewriting the Lightsaber header to match what fits on a 112-byte sticker and seeing how the brick reacts. For normal cloning, prefer `NfcClone.run/1`.

## List ports

To see available serial ports (e.g. to find the Arduino):

```bash
mix run -e "MacCapture.list_ports()"
```

