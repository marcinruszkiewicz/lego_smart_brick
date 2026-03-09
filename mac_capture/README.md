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

With auto-detected USB serial port (first port with `usbmodem` in the name):

```bash
mix run -e "NfcCapture.run()"
```

With an explicit port:

```bash
mix run -e "NfcCapture.run(port: \"/dev/cu.usbmodem14101\")"
```

Output is written to `nfc_dump_YYYY-MM-DD.jsonl` in the current directory. Each line is one JSON object: `uid`, `afi`, `dsfid`, `blocks`.

Press **Ctrl+C** to stop.

## List ports

To see available serial ports (e.g. to find the Arduino):

```bash
mix run -e "MacCapture.list_ports()"
```
