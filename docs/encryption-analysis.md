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

| Parameter | Value | Source |
|-----------|-------|--------|
| Algorithm | AES-CCM | Firmware strings |
| Key size | 16 bytes | Disassembly (`mov_s r3, 0x10`) |
| Key storage | HW register 0x808904 | Disassembly trace |
| Nonce length | Unknown (7-13 bytes per CCM spec) | — |
| MAC length | Unknown (4, 8, or 16 bytes) | — |
| AAD | Unknown (possibly empty, header, or tag metadata) | — |

### Decrypted data structure (from SmartAssist app analysis)

After decryption, the plaintext is expected to be TLV-structured:

```
Bytes 0-1:  Type ID (12-bit type + 2-bit block_type in bits 12-13)
Bytes 2-3:  Content length (uint16 LE)
Bytes 4-7:  Event type magic:
              Identity tags: 0xA7E24ED1 (LE: D1 4E E2 A7)
              Item tags:     0x0BBDA113 (LE: 13 A1 BD 0B)
```

These magic values provide known-plaintext targets for validating decryption attempts.

## Firmware architecture

- **MCU:** ARC EM architecture (likely EM9305)
- **Firmware format:** `~P11` signed containers
- **AES engine:** Hardware-accelerated, memory-mapped at `0x808800`–`0x8089FF`
- **No AES S-box** in the binary (confirming hardware acceleration)
- **Flash base address:** `0x306000`

### Key crypto functions

| Address | Role |
|---------|------|
| 0x03CA00 | Crypto init — loads AES key from HW register |
| 0x03C984 | Tag slot config — initializes 4 slot types (R/S/T/U) |
| 0x025718 | Tag data processing — most complex crypto function |
| 0x025C50 | Error handler for AES-CCM failures |
| 0x03E67C | Tag reader function |

### Tag slot types

The firmware manages 4 tag slot types: R (0x52), S (0x53), T (0x54), U (0x55) — likely Read, Security/Sign, Tag, Update/User.

Full disassembly trace details: [firmware/DISASM_TRACE_FINDINGS.md](../firmware/DISASM_TRACE_FINDINGS.md).

## Bilbo backend

LEGO's backend platform "Bilbo" manages smart brick devices. Probed endpoints:

| Endpoint | Status | Notes |
|----------|--------|-------|
| `aup.bilbo.lego.com/health` | 200 OK | Health check active |
| `enigma.bilbo.lego.com/...` | 404/405 | Crypto/key services, needs `x-api-key` |
| `rango.bilbo.lego.com/...` | 404/405 | Element/tag services, needs `x-api-key` |

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

2. **MITM the SmartAssist app** — Intercept traffic between the app and Bilbo backend during tag scanning. The key may be provisioned over the network (via Enigma service).

3. **IL2CPP analysis** — The SmartAssist app (Unity/IL2CPP) has been dumped. Deeper analysis of the tag processing code may reveal how the key is obtained or used.

4. **Cloned tag + key brute force** — Write known plaintext to a blank tag (if the brick encrypts on write), then compare encrypted output to constrain key/nonce space. Requires understanding the write-side protocol.

5. **Community collaboration** — If the key is global (same across all devices, which identical-payload evidence suggests), anyone with debug access to one brick can recover it for all.

## What works without the key

**Byte-perfect cloning** — Since all tags of the same type have identical encrypted content, and the smart brick reads data (not UID), copying the raw bytes to a blank writable tag produces a functional clone. No decryption needed.

See [cloning-guide.md](cloning-guide.md) for the practical cloning workflow.
