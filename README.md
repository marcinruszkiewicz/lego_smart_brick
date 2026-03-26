# LEGO Smart Brick NFC Tag Toolkit

Read, analyze, and clone **ISO 15693 (NFC Type 5)** tags from the LEGO smart brick system using a PN7150 reader, ESP32, and an Elixir app on the Mac. Includes firmware reverse-engineering tools and encryption analysis scripts.

## What's in this repo


| Path               | Description                                                                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **nfc_tool/**      | Arduino sketch (ESP32 + PN7150). Reads and writes ISO 15693 tags over serial. Supports a `CLONE:` command protocol driven from the Mac.            |
| **mac_capture/**   | Elixir app. Three modes: **capture** (read tags and save), **analyze** (diff/compare dumps), and **clone** (write a saved tag to a blank sticker). |
| **smart_brick/**   | Elixir app that provides a CLI to connect to a smart brick with BLE and interact with it.                                                          |
| **firmware/**      | Python scripts for firmware analysis: extraction, disassembly, crypto tracing, key candidate extraction, and Bilbo API probing.                    |
| **crypto_attack/** | C prototype for Grain-128A key recovery (guess-and-determine attack). See [crypto_attack/README.md](crypto_attack/README.md).                      |
| **data/**          | Saved tag dumps (`.jsonl`), candidate AES keys, and reference tag data from [node-smartplay](https://github.com/nathankellenicki/node-smartplay).  |
| **docs/**          | Technical findings: tag format, NFC chip ID, encryption analysis, cloning guide.                                                                   |


## Hardware

- **Board:** Wemos D1 R32 (ESP32) — chosen for Uno-compatible shield layout.
- **NFC:** PN7150 (OM5578/PN7150ARDM shield). Required because the more common PN532 cannot read ISO 15693 tags.
- **Tags:** ISO 15693 / Type 5 — specifically EM Microelectronic EM4233 (2k-bit EEPROM).
- **Clone targets:** Blank EM4233-compatible ISO 15693 tag stickers (NFC Type 5, writable).

Wiring and pinout are documented in the `nfc_tool.ino` sketch header.

## Quick start

### 1. Read tags (capture mode)

```bash
# Flash the Arduino sketch, then:
cd mac_capture && mix deps.get
mix run -e "NfcCapture.run()"
```

Present a tag; type what you're scanning when prompted. Each tag is appended to `data/nfc_dump_YYYY-MM-DD.jsonl`.

### 2. Analyze dumps

```bash
mix run -e "NfcAnalyze.run()"
# or with a specific file:
mix run -e 'NfcAnalyze.run("../data/hardware_md_tag_dumps.jsonl")'
```

### 3. Clone a tag to a blank sticker

```bash
mix run -e "NfcClone.run()"
```

Presents a menu of all saved tags (deduplicated), sends the data to the Arduino, and writes block-by-block with read-back verification. See [docs/cloning-guide.md](docs/cloning-guide.md) for details.

## LEGO smart tag findings

### NFC chip

The tags use a **custom EM Microelectronic die** (IC ref 0x17, matching the **EM4237** — not EM4233 as initially assumed). UID prefix `E016` = EM Microelectronic. The EM4237 implements **Grain-128A** (ISO/IEC 29167-13) encryption. Each tag has 66 blocks × 4 bytes = 264 bytes of EEPROM. All data blocks on factory tags are **permanently write-locked**.

### Data format

- **Block 0 (header):** `[payload_len_hi, payload_len_lo, 0x01, 0x0C]` — payload length in bytes, followed by fixed tag capacity (0x010C = 268).
- **Blocks 1–N:** Encrypted binary payload (Grain-128A stream cipher). Not NDEF, not readable ASCII.
- **Remaining blocks:** Zero-padded (`00000000`), then two `0001` filler blocks at end-of-memory.

### Encryption

The payload is most likely encrypted with **Grain-128A** (ISO/IEC 29167-13), a lightweight stream cipher with 128-bit key and 96-bit IV. Key findings:

- The encryption runs inside the **DA000001-01 ASIC** — the EM9305 firmware never sees encrypted tag data. The AES-CCM functions in the EM9305 are for BrickNet PAwR / ASIC mutual authentication, not tag decryption.
- The 128-bit key is **in the ASIC silicon** — shared across all bricks (all bricks decrypt all tags). Not accessible from the EM9305 firmware or via JTAG.
- Each tag carries a **per-content 96-bit IV** (first 12 bytes of the encrypted region). Same content → same IV → identical ciphertext regardless of UID.
- **320 bits of known keystream** have been derived from 4 ship tags using known plaintext structure, massively over-determining the 128-bit key — but inverting Grain-128A's 256 nonlinear init rounds remains computationally infeasible.

See [docs/encryption-analysis.md](docs/encryption-analysis.md), [firmware/DISASM_TRACE_FINDINGS.md](firmware/DISASM_TRACE_FINDINGS.md), and [node-smartplay HARDWARE.md](https://github.com/nathankellenicki/node-smartplay/blob/main/notes/HARDWARE.md).

### Cloning feasibility

Since all tags of the same type share identical encrypted payloads (regardless of UID), and the data is openly readable, **byte-perfect cloning to a blank writable tag produces a functionally identical tag**. The smart brick reads tag data, not UID. Cloning works even when the blank has a different UID or chip vendor (e.g. LEGO tags use a custom EM die, UID prefix `E016`; blanks with prefix `E004` or other ISO 15693 chips behave the same once the payload is written). Smaller blanks (e.g. 112 bytes = 28 blocks) work for tags that fit — R2-D2, Tie Fighter, and X-Wing; larger identities need more capacity (see [docs/cloning-guide.md](docs/cloning-guide.md)).

## Docs

- **[docs/lego-smart-brick-nfc-comparison.md](docs/lego-smart-brick-nfc-comparison.md)** — Block-by-block comparison, header layout, chip identification.
- **[docs/encryption-analysis.md](docs/encryption-analysis.md)** — Consolidated encryption/crypto analysis and key recovery options.
- **[docs/cloning-guide.md](docs/cloning-guide.md)** — How to clone tags: compatible stickers, workflow, troubleshooting.
- **[docs/spi-sniffing-guide.md](docs/spi-sniffing-guide.md)** — SPI bus sniffing to capture decrypted tag plaintext from the ASIC.
- **[docs/community-sync.md](docs/community-sync.md)** — Coordination notes with the [node-smartplay](https://github.com/nathankellenicki/node-smartplay) project.
- **[docs/additional-info.md](docs/additional-info.md)** — External resources and links.
- **[firmware/DISASM_TRACE_FINDINGS.md](firmware/DISASM_TRACE_FINDINGS.md)** — Detailed firmware disassembly trace of AES key loading.

## Firmware tools


| Script                | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `extract_firmware.py` | Extract firmware images from update packages.                           |
| `parse_firmware.py`   | Parse `~P11` signed container format.                                   |
| `disassemble.py`      | Disassemble ARC EM architecture firmware.                               |
| `trace_crypto.py`     | Trace AES key loading and crypto register access in disassembly.        |
| `extract_keys.py`     | Extract high-entropy 16-byte candidate AES keys from firmware binaries. |
| `find_tag_crypto.py`  | Locate tag crypto functions and string references.                      |
| `analyze_tags.py`     | Analyze tag dump structure and patterns.                                |
| `probe_bilbo.py`      | Probe LEGO's Bilbo backend API endpoints.                               |


### Grain-128A decryption tools (Elixir, in `mac_capture/`)


| Module             | Purpose                                                                                                                                                                                                                     |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Grain128a`        | Grain-128A stream cipher (ISO/IEC 29167-13); 128-bit key, 96-bit IV. Run `mix run -e "Grain128a.self_test()"`.                                                                                                              |
| `GrainExperiments` | Tag decryption experiments: IV extraction, known-plaintext keystream verification (320-bit constraint from 4 ship tags), XOR analysis, key candidate search. Run `mix run -e "GrainExperiments.run()"` from `mac_capture/`. |


## Requirements

- **Arduino:** ESP32 board support, [ElectronicCats PN7150](https://github.com/ElectronicCats/ElectronicCats-PN7150) library.
- **Mac:** Elixir 1.18+ (for built-in `JSON` module), `circuits_uart`. Run `mix deps.get` in `mac_capture/`.
- **Firmware tools:** Python 3 with `requests` (for Bilbo probing). A venv is set up in `firmware/`.

