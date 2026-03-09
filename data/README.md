# Data directory

- **`nfc_dump_YYYY-MM-DD.jsonl`** — Captured tag dumps from the NFC tool (one JSON object per line). Label with `item` when capturing.
- **`hardware_md_tag_dumps.jsonl`** — Tag dumps converted from [node-smartplay HARDWARE.md](https://github.com/nathankellenicki/node-smartplay/blob/main/notes/HARDWARE.md). Same format: `uid`, `afi`, `dsfid`, `blocks`, `item`. Use with the analyzer:
  ```bash
  cd mac_capture && mix run -e "NfcAnalyze.run(\"../data/hardware_md_tag_dumps.jsonl\")"
  ```
Tag format: `uid` is 16 hex chars (no colons); `blocks` is an array of 4-byte blocks as 8 hex chars each; optional trailing `"0001"` filler blocks match the NFC reader’s past-end detection.
