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

Output is written to `nfc_dump_YYYY-MM-DD.jsonl` in the `../data` directory. Each line is one JSON object: `uid`, `afi`, `dsfid`, `blocks`.

Press **Ctrl+C** to stop.

### Clone (write a saved tag to a blank tag)

Clone mode loads saved dumps from `../data/*.jsonl`, shows a menu, then sends a `CLONE:<hex>` command to the Arduino and writes the blocks to a presented blank tag.

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

## List ports

To see available serial ports (e.g. to find the Arduino):

```bash
mix run -e "MacCapture.list_ports()"
```

