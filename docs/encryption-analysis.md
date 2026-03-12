# LEGO Smart Brick NFC Tag Encryption Analysis

## Overview

LEGO smart brick NFC tags store encrypted data payloads using **AES-128-CCM** (Counter with CBC-MAC). This document consolidates all findings from firmware disassembly, tag data analysis, and decryption attempts.

## Tag data layout

```
Byte 0-1:  Payload length (big-endian, e.g. 0x00A9 = 169 bytes)
Byte 2-3:  0x01 0x0C (fixed tag capacity = 268 bytes)
Byte 4:    0x01 (security format version)
Byte 5+:   AES-CCM encrypted blob
```

The encrypted region starts at byte 5. Everything before that is cleartext header.

## What we know about the encryption

### Algorithm: AES-128-CCM

Confirmed by firmware log strings:

- `AES-CCM context create failed Result={}`
- `AES_CCM_DecryptAndMAC failed Result={}`
- `AES_CCM_GetMAC failed Result={}`
- `AES_CCM MAC verification failed`
- `Tag security verification passed`

### Key size: 16 bytes (AES-128)

Confirmed by disassembly of the crypto init function at `0x03CA00`:

```
mov_s r3, 0x10    ; r3 = 16 = AES-128 key size
```

### Key location: hardware register 0x808904

The key is **not stored in the firmware binary**. It lives in a hardware key register on the MCU (likely EM9305 OTP/key slot memory). The crypto init function reads 16 bytes from `0x808904` into the AES engine at `0x80884c`.

This means the key cannot be extracted by analyzing firmware update files alone.

### Nonce is NOT derived from UID

Two different Vader minifigure tags with different UIDs (`E0165C011FC66027` and `E0165C011FC88E45`) contain **byte-identical encrypted payloads**. This proves:

1. The encryption key is the same across tags (global, not per-tag).
2. The nonce/IV is the same for the same plaintext (likely deterministic from the data, not from UID).
3. All tags of the same "type" encrypt to the same ciphertext.

### Known AES-CCM parameters (partial)


| Parameter    | Value                                             | Source                         |
| ------------ | ------------------------------------------------- | ------------------------------ |
| Algorithm    | AES-CCM                                           | Firmware strings               |
| Key size     | 16 bytes                                          | Disassembly (`mov_s r3, 0x10`) |
| Key storage  | HW register 0x808904                              | Disassembly trace              |
| Nonce length | Unknown (7-13 bytes per CCM spec)                 | —                              |
| MAC length   | Unknown (4, 8, or 16 bytes)                       | —                              |
| AAD          | Unknown (possibly empty, header, or tag metadata) | —                              |


### Decrypted data structure (TLV)

After decryption, the plaintext is **expected** to be TLV-structured. This has not been verified by successfully decrypting a tag (the key is in hardware and we do not have it):

```
Bytes 0-1:  Type ID (12-bit type + 2-bit block_type in bits 12-13)
Bytes 2-3:  Content length (uint16 LE)
Bytes 4-7:  Event type magic (uint32 LE). All known values accepted for decryption validation:
              Identity / alias / presence: 0xA7E24ED1 (LE: D1 4E E2 A7)
              Item (tile):                0x0BBDA113 (LE: 13 A1 BD 0B)
              Play command:               0x812312DC (LE: DC 12 23 81)
              Distributed play (PAwR):    0x814A0D84 (LE: 84 0D 4A 81)
              Status/position:            0xE3B77171 (LE: 71 71 B7 E3)
```

**Confirmed from firmware:** In fw_v1.119.0, the callee **0xfe14** (reached from tag data processing 0x25718) loads a halfword at offset 0, a halfword at offset 2, and a word at offset 4 from the decrypted buffer, and compares the value at 4 — matching the expected TLV layout (type_id @ 0, content_len @ 2, event magic @ 4). See [firmware/ANALYZE_TAG_TLV.md](../firmware/ANALYZE_TAG_TLV.md) 

The **magic constants** 0xA7E24ED1 / 0x0BBDA113 have **not** been found in code.bin, rofs_files/play, or as immediates in the disassembly; run `firmware/find_magic_constants.py fw_v1.119.0` to reproduce the search. They may be in another ROFS file, computed from type_id, or in a literal pool; see [firmware/ANALYZE_TAG_TLV.md](../firmware/ANALYZE_TAG_TLV.md) §8.

**Provenance:** The numeric values (and the full event-type table) are taken from [node-smartplay HARDWARE.md](https://github.com/nathankellenicki/node-smartplay/blob/main/notes/HARDWARE.md#tag-content-data), which attributes them to firmware debug strings (v0.46–v0.54) and disassembly of v0.72.1. The firmware we analyze (build label fw_v1.119.0) has **ROFS content version 0.46.0** (from `rofs_files/version`), i.e. the same generation HARDWARE.md cites — yet the magic constants do not appear as 4-byte literals in code.bin or play. So they may have been inferred from behaviour/disassembly, or appear only in a different build or encoding. 

## Firmware architecture

- **MCU:** ARC EM architecture (likely EM9305)
- **Firmware format:** `~P11` signed containers
- **AES engine:** Hardware-accelerated, memory-mapped at `0x808800`–`0x8089FF`
- **No AES S-box** in the binary (confirming hardware acceleration)
- **Flash base address:** `0x306000`

### Key crypto functions


| Address  | Role                                                 |
| -------- | ---------------------------------------------------- |
| 0x03CA00 | Crypto init — loads AES key from HW register         |
| 0x03C984 | Tag slot config — initializes 4 slot types (R/S/T/U) |
| 0x025718 | Tag data processing — most complex crypto function   |
| 0x025C50 | Error handler for AES-CCM failures                   |
| 0x03E67C | Tag reader function                                  |


### Tag slot types

The firmware manages 4 tag slot types: R (0x52), S (0x53), T (0x54), U (0x55) — likely Read, Security/Sign, Tag, Update/User.

Full disassembly trace details: [firmware/DISASM_TRACE_FINDINGS.md](../firmware/DISASM_TRACE_FINDINGS.md).

## Bilbo backend

LEGO's backend platform "Bilbo" manages smart brick devices. Probed endpoints:


| Endpoint                    | Status  | Notes                                   |
| --------------------------- | ------- | --------------------------------------- |
| `aup.bilbo.lego.com/health` | 200 OK  | Health check active                     |
| `enigma.bilbo.lego.com/...` | 404/405 | Crypto/key services, needs `x-api-key`  |
| `rango.bilbo.lego.com/...`  | 404/405 | Element/tag services, needs `x-api-key` |


The Enigma service has endpoints like `CreateSpkitBundle` and `SharedKey` that may be involved in key provisioning. Access requires authentication.

## Decryption attempts so far

### Firmware key extraction (`firmware/extract_keys.py`)

Extracted ~1,100 candidate 16-byte keys from firmware binaries using entropy filtering and alignment heuristics. None produced valid AES-CCM decryptions — consistent with the key being in hardware, not firmware.

### AES-CCM brute force (`mac_capture/lib/nfc_decrypt.ex`)

Tried all candidate keys with multiple parameter combinations:

- Nonce lengths: 7, 8, 10, 11, 12, 13 bytes
- MAC lengths: 4, 8, 16 bytes
- Nonce derivation: embedded in data, header-derived, fixed zeros
- Result: no valid decryptions (authentication tag mismatch on all attempts)

### Other ciphers tested

- Single-byte XOR
- Two-byte repeating XOR
- TEA / XTEA
- RC4
- AES-ECB / AES-CBC with various keys

None produced structured output matching the expected TLV format.

## Key recovery options

Since the key is in hardware, the remaining paths to obtain it are:

1. **JTAG/debug access** — Read register `0x808904` from a running smart brick MCU. Requires physical access to debug pads on the PCB.
2. **MITM the SmartAssist app** — Intercept traffic between the app and Bilbo backend. Less likely to yield the tag key: tags work on any brick globally, so the key is probably not reprovisioned per device via the app when docked; it is likely baked into the brick (e.g. OTP). Enigma might still be relevant for other keys (e.g. firmware signing).
3. **Cloned tag + key brute force** — Write known plaintext to a blank tag (if the brick encrypts on write), then compare encrypted output to constrain key/nonce space. Requires understanding the write-side protocol.
4. **Community collaboration** — Tags are the same globally and can be read by any smart brick, so the key is global (not per-device). Identical-payload evidence already suggests this. Anyone with debug access to one brick (e.g. JTAG read of 0x808904) can recover the key for all.

## What works without the key

**Byte-perfect cloning** — Since all tags of the same type have identical encrypted content, and the smart brick reads data (not UID), copying the raw bytes to a blank writable tag produces a functional clone. No decryption needed.

See [cloning-guide.md](cloning-guide.md) for the practical cloning workflow.