# ISO 15693 Tag Emulation — Plan and Options

This document captures research on whether and how to **emulate** an ISO 15693 (NFC Type 5) tag so a LEGO smart brick sees a device as a tag, rather than only reading/writing physical stickers. **Not planned for implementation right now** — kept for future reference.

---

## Can the PN7150 Pretend to Be a Tag?

**No.** The PN7150 can **read and write** ISO 15693 tags but **cannot emulate** them.

- PN7150 card emulation (per NXP/NCI) supports **Type 4** (ISO 14443 A/B) and **Type 3** (FeliCa).
- **Type 5 (ISO 15693)** is not supported in PICC/card-emulation mode. The chip talks 15693 only as a **reader** (VCD).

So: the existing [nfc_tool/nfc_tool.ino](../nfc_tool/nfc_tool.ino) flow (read, clone to blank sticker via `CLONE:`) is the way to get a physical tag the brick can read. The PN7150 cannot present itself as that tag.

---

## iOS App — Can the iPhone Pretend to Be a Tag?

**No.** Apple does not allow third-party apps to do generic NFC tag/card emulation.

- Core NFC supports **reading** (and in some cases **writing**) tags; the phone acts as a reader, not as an emulated tag.
- Card emulation (HCE) from iOS 17.4 via `CardSession` is **restricted** to approved use cases (payments, car keys, transit, home/hotel keys, corporate badges, etc.) and requires an **Apple entitlement**. You cannot use it to emulate an arbitrary ISO 15693 LEGO tag.

There is no iOS app that can make the iPhone act as a LEGO (Type 5) tag.

---

## Hardware Options for 15693 Emulation (Ready-Made)

### PN532Killer — budget option (~$30)

- **Price:** ~$30 (pn532killer.com)
- **15693:** Reader, **emulator**, and sniffer. Emulates ICODE SLIX-L, ICODE SLIX, Tag-it HF-I PLUS (all ISO 15693).
- **Caveat:** LEGO uses **EM4233** (EM Microelectronic); PN532Killer emulates NXP ICODE / TI Tag-it. Protocol is standard 15693, so the brick might accept it; compatibility would need testing.
- **Interface:** USB and BLE; can be driven from the Mac (e.g. serial/CLI).

**Verdict:** Lowest-cost ready-made 15693 emulator. Best option to try “device as tag” without Proxmark3.

### ChameleonMini RevG — limited availability

- **Status:** Discontinued in favor of Chameleon Ultra; some stock still sold:
  - ProxGrind (chameleontiny.com): ~$99 — often **out of stock**
  - Kasper & Oswald (shop.kasper.it): ~€150
  - Attify Store: ~$140
- **15693:** Original ChameleonMini (RevG) **does** support ISO 15693 emulation. **Chameleon Ultra** and **Chameleon Lite** do **not** (14443A + LF only). For 15693 you need RevG, not Ultra/Lite.

### Chameleon Ultra / Chameleon Lite — not for LEGO

- Support ISO 14443A (MIFARE, NTAG, Ultralight) and 125 kHz LF only. No ISO 15693. Not suitable for “pretend to be a LEGO tag.”

### Proxmark3

- Full 15693 simulation/emulation and tooling; **expensive** and overkill for this use case.

### Summary (ready-made)

| Option                 | 15693 emulation | Cost       | Note                                          |
| ---------------------- | --------------- | ---------- | --------------------------------------------- |
| **PN532Killer**        | Yes (ICODE etc.)| ~$30       | Available; LEGO/EM4233 compatibility TBD      |
| **ChameleonMini RevG** | Yes             | ~$99–150   | Limited stock (try Kasper & Oswald, Attify)   |
| **Chameleon Ultra/Lite** | No            | —          | 14443 only; not for LEGO                       |
| **Proxmark3**          | Yes             | High       | Too expensive for this project                |
| **iOS app**            | No              | —          | Apple does not allow generic tag emulation    |

---

## DIY: ESP32 + Available Boards/Modules

There is **no** common “ESP32 + one breakout” path: off-the-shelf NFC modules (PN7150, PN5180, PN532, RC522, etc.) are either 15693 **readers only** or support **14443** card emulation only, not 15693 tag emulation.

### 1. TI RF430FRL152H — programmable 15693 transponder

**Idea:** Use a chip that **is** an ISO 15693 tag and program it with cloned LEGO data. No ESP32 in the RF path; the RF430 is the tag.

- **RF430FRL152H / RF430FRL154H:** Single-chip 13.56 MHz transponder with built-in MSP430, FRAM (2 KB), ISO 15693 RF. Supports Get System Info, Read Single Block (0x20), Write Single Block (0x21), Lock Block, etc.
- **Hardware:** [RF430FRL152HEVM](https://www.ti.com/tool/RF430FRL152HEVM) (evaluation board, ~$50–100).
- **Flow:** Clone a LEGO tag with PN7150 + nfc_tool → export UID + 66 blocks (264 bytes) → program RF430 FRAM (and UID if supported) via TI tools → present board to brick.
- **Caveats:** Confirm whether RF430 allows **custom UID**; LEGO may rely on UID. EVM is a dev board, not a tiny keyfob.
- **ESP32:** Optional for data prep; the tag the brick sees is the RF430.

**Verdict:** Best “DIY with a module/board” path; no custom RF. Need to confirm custom UID and memory layout vs LEGO.

### 2. TRF7970A in “Direct Mode” + MCU

- TRF7970A does **not** support 15693 tag emulation in standard firmware. TI forums suggest **Direct Mode** so the MCU drives RF modulation.
- **Idea:** ESP32 (or other MCU) + TRF7970A over SPI: TRF7970A gives demodulated reader commands; MCU implements 15693 tag response and, in direct mode, drives modulator (423.75 kHz subcarrier, Manchester, etc.).
- **Reality:** Full 15693 **tag** side in firmware + TRF7970A direct-mode and antenna design. No ready-made 15693 tag emulator library for TRF7970A + ESP32. Substantial project.

**Verdict:** Only if you want to go deep on protocol and RF; not a quick “spare ESP32 + one board” solution.

### 3. Full custom: MCU + discrete RF

- **Concept:** Tag entirely in software: **receive** reader commands (demodulate 13.56 MHz ASK), **send** responses by **load modulation** at 423.75 kHz (fc/32) with Manchester-coded data.
- **Hardware:** Antenna (13.56 MHz), **demodulator** (reader → MCU), **modulator** (MCU → reader via GPIO + transistor switching load on antenna).
- **MCU:** ESP32 (or C8051F/STM32) runs 15693 state machine and drives modulator timing.
- **Reference:** Implementations exist (e.g. [nfc15693.com](http://www.nfc15693.com/eindex.htm)) with “C8051F/STM32 + 2-wire I/O + receive circuit” and passive tag simulation with common components. ChameleonMini RevG does 15693 emulation with ATxmega + custom RF front-end (schematics in their repo).

**Verdict:** Maximum flexibility; requires custom analog/RF design and protocol stack. Not “ESP32 + some available boards” in the usual sense.

### 4. ESP32 + reader modules only — cannot emulate

- **PN7150** (current setup): 15693 reader/writer only; no tag emulation.
- **PN5180:** 15693 reader; card emulation is **14443 only**.
- **PN532, RC522:** 14443 only.

No combination of ESP32 + these modules can make the LEGO brick see the device as a 15693 tag. A tag-side RF path (RF430, TRF7970A direct mode, or custom modulator/demodulator) would still be required.

### Summary (DIY)

| Approach                 | Hardware                          | ESP32 role                    | Effort      | 15693 tag emulation                |
| ------------------------ | --------------------------------- | ----------------------------- | ----------- | ---------------------------------- |
| **TI RF430FRL152H**      | RF430FRL152HEVM (~$50–100)        | Optional (data prep)          | Low–medium  | Yes, if UID/memory fits LEGO       |
| **TRF7970A direct mode**| TRF7970A board + antenna          | Protocol + drive TRF7970A     | High        | Theoretically yes                  |
| **Full custom**          | Antenna + demod + load modulator  | Full 15693 tag + modulation   | Very high   | Yes                                |
| **PN7150 / PN5180 / PN532** | Existing or similar           | N/A                           | —           | **No** (reader only for 15693)     |

---

## Practical Takeaway

- **Today:** Use the existing **clone-to-blank-sticker** flow (ESP32 + PN7150 + `CLONE:` in nfc_tool) to get a physical tag the brick can read.
- **If you later want “device as tag” without swapping stickers:** Try **PN532Killer** (~$30) first for a ready-made emulator; or **TI RF430FRL152H** (EVM) for a programmable 15693 transponder you load with cloned data. Confirm UID and block layout vs LEGO’s expectations in both cases.
