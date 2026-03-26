# LEGO Smart Brick NFC Tag Encryption Analysis

## Overview

LEGO smart brick NFC tags store encrypted data payloads using - most likely at the point of the writing - **Grain-128A** (ISO/IEC 29167-13), a lightweight stream cipher with a 128-bit key and 96-bit IV. The encryption and decryption are handled entirely by the **DA000001-01 ASIC** — the EM9305 BLE SoC never sees encrypted tag data.

> **Note on AES-CCM:** Earlier versions of this document attributed the tag encryption to AES-128-CCM based on firmware log strings (`AES-CCM context create failed`, `AES_CCM_DecryptAndMAC failed`, etc.). Per [node-smartplay HARDWARE.md](https://github.com/nathankellenicki/node-smartplay/blob/main/notes/HARDWARE.md), the AES-CCM functions in the EM9305 firmware are for **BrickNet PAwR session encryption** and **EM9305↔ASIC mutual authentication**, not tag data decryption. The EM9305 never sees encrypted tag data — the ASIC reads, decrypts, and deposits structured TLV plaintext into EM9305 registers over SPI.

## Tag data layout

```
Byte 0-1:  Payload length (big-endian, e.g. 0x00A9 = 169 bytes)
Byte 2-3:  0x01 0x0C (fixed tag capacity = 268 bytes)
Byte 4:    0x01 (security format version)
Byte 5-16: Per-content IV (96 bits / 12 bytes) — unique per tag content type
Byte 17+:  Grain-128A ciphertext (keystream XOR plaintext)
```

The encrypted region starts at byte 5. The first 12 bytes of the encrypted region are the per-content IV used to initialize the Grain-128A cipher. The remaining bytes are ciphertext. There may be a MAC (0-8 bytes) at the end of the payload.

## What we know about the encryption

### Algorithm: Grain-128A (ISO/IEC 29167-13) is a good guess

**Evidence:**

1. Tag IC reference **0x17** matches EM Microelectronic's **EM4237**, which implements Grain-128A
2. Tag memory layout (66 blocks × 4 bytes) matches EM4237
3. Payload sizes (69–166 bytes of encrypted data) are **not multiples of any block cipher block size** — consistent with a stream cipher
4. EM Microelectronic uses Grain-128A across their ISO 15693 product line (EM4237, EM4333)
5. Grain-128A is a lightweight LFSR+NFSR stream cipher feasible for a small mixed-signal ASIC

### Key size: 128 bits (16 bytes)

Standard Grain-128A parameter. The key initializes the 128-bit NFSR (Nonlinear Feedback Shift Register).

### IV size: 96 bits (12 bytes)

Standard Grain-128A parameter. The IV initializes the 128-bit LFSR as: `IV(96 bits) || ones(31 bits) || 0`. Each tag content type has a unique IV embedded in the encrypted region at bytes 5-16.

### Key location: DA000001-01 ASIC silicon

The Grain-128A decryption key is **not in the EM9305 firmware or its registers**. It resides in the DA000001-01 custom LEGO ASIC. All bricks share the same decryption capability (any brick decrypts any tag), so the key is global — likely a silicon constant or OTP value in the ASIC.

**What about register 0x808904?** The AES hardware at `0x808800`–`0x8089FF` and the key at `0x808904` on the EM9305 are used for BrickNet PAwR encryption and EM9305↔ASIC mutual authentication. They are not involved in tag decryption.

### Nonce/IV is NOT derived from UID

Two different Vader minifigure tags with different UIDs (`E0165C011FC66027` and `E0165C011FC88E45`) contain **byte-identical encrypted payloads**. This proves:

1. The encryption key is the same across tags (global, not per-tag).
2. The IV is the same for the same content (embedded in the payload, not from UID).
3. All tags of the same "type" encrypt to the same ciphertext.
4. Different clones to the same UID copy still work

### Per-content IV confirmed by XOR analysis

Exhaustive pairwise XOR analysis across 14 unique tag dumps (91 pairs) found no shared keystream at any ciphertext offset — ruling out a static nonce. Each tag has a unique 12-byte IV at bytes 5-16, different for each content type but identical across physical copies of the same content.

### Known parameters


| Parameter   | Value                                             | Source                                |
| ----------- | ------------------------------------------------- | ------------------------------------- |
| Algorithm   | Grain-128A (ISO/IEC 29167-13)                     | IC ref 0x17 = EM4237                  |
| Key size    | 128 bits (16 bytes)                               | Grain-128A standard                   |
| IV size     | 96 bits (12 bytes)                                | Grain-128A standard                   |
| IV location | Bytes 5-16 of tag payload                         | XOR analysis + per-content uniqueness |
| Key storage | DA000001-01 ASIC silicon                          | ASIC handles all tag decryption       |
| MAC length  | Unknown (0-4 bytes, Grain-128A supports 0-32 bit) | —                                     |


### Decrypted data structure (TLV)

After decryption, the plaintext is TLV-structured. From [node-smartplay FLOW.md](https://github.com/nathankellenicki/node-smartplay/blob/main/notes/FLOW.md), the ASIC deposits a **type 0x22 TLV container** with sub-records into EM9305 registers:

- Sub-record format: `[type:1][param:1][length:1][payload:N]`
- Content identity record: 7 bytes `{content_lo(u32), content_hi(u16), type_byte(u8)}`
- Resource reference records: `{content_ref_start(u16), content_ref_end(u16), bank_index(u16), bank_ref(u16)}`

The event type magics (confirmed in fw v2.29.1 disassembly as immediates at function 0x66c74):


| Event type              | Magic (LE) | Hex bytes   |
| ----------------------- | ---------- | ----------- |
| Identity / alias        | 0xA7E24ED1 | D1 4E E2 A7 |
| Item (tile)             | 0x0BBDA113 | 13 A1 BD 0B |
| Play command            | 0x812312DC | DC 12 23 81 |
| Distributed play (PAwR) | 0x814A0D84 | 84 0D 4A 81 |
| Status/position         | 0xE3B77171 | 71 71 B7 E3 |


### Known plaintext and keystream (from node-smartplay)

For the 4 ship tags (X-Wing, TIE, Falcon, A-Wing — all 90-byte plaintext), **10 firm known plaintext bytes** at offsets 53-69 have been identified from firmware dispatch chain tracing. Combined with 4 tags, this gives **320 bits of keystream constraint** on the 128-bit key (massively over-determined).

The known keystream bytes have been verified against our tag dumps — all 30 checks pass (3 of 4 ship tags in our data). See `mac_capture/lib/grain_experiments.ex` for the verification code.

## Architecture

### Two-chip system


| Chip                 | Role in tag processing                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **DA000001-01 ASIC** | Reads tags via NFC coils, decrypts Grain-128A payload internally, deposits structured TLV into EM9305 registers over SPI |
| **EM9305 BLE SoC**   | Receives decrypted TLV data, runs play engine, handles BLE. AES-CCM used for BrickNet PAwR and ASIC mutual auth only     |


The EM9305 firmware never constructs ISO 15693 commands, never sees encrypted tag data, and never touches the Grain-128A decryption key. All tag crypto is in the ASIC.

### EM9305 AES-CCM (BrickNet, not tags)

The AES-CCM functions found in EM9305 firmware are for:

1. **BrickNet PAwR session encryption** — encrypted communication between bricks
2. **EM9305↔ASIC mutual authentication** — during ASIC init, the EM9305 copies a 16-byte key from config struct `0x80DCE4+0x26` to ASIC register `0xF04084`

Firmware log strings that were previously attributed to tag decryption:

- `AES-CCM context create failed Result={}` — BrickNet/ASIC-auth
- `AES_CCM_DecryptAndMAC failed Result={}` — BrickNet/ASIC-auth
- `AES_CCM_GetMAC failed Result={}` — BrickNet/ASIC-auth
- `AES_CCM MAC verification failed` — BrickNet/ASIC-auth
- `Tag security verification passed` — post-ASIC validation (firmware side, after ASIC decryption)

### Key crypto functions (EM9305 — BrickNet/ASIC-auth, NOT tag decryption)


| Address  | Role                                                                  |
| -------- | --------------------------------------------------------------------- |
| 0x03CA00 | Crypto init — loads AES key from HW register (for BrickNet/ASIC-auth) |
| 0x03C984 | Tag slot config — initializes 4 slot types (R/S/T/U)                  |
| 0x025718 | Tag data processing — processes decrypted TLV from ASIC               |
| 0x025C50 | Error handler for AES-CCM failures (BrickNet)                         |
| 0x03E67C | Tag reader function                                                   |


Full disassembly trace details: [firmware/DISASM_TRACE_FINDINGS.md](../firmware/DISASM_TRACE_FINDINGS.md).

## Bilbo backend

LEGO's backend platform "Bilbo" manages smart brick devices. Probed endpoints:


| Endpoint                    | Status  | Notes                                   |
| --------------------------- | ------- | --------------------------------------- |
| `aup.bilbo.lego.com/health` | 200 OK  | Health check active                     |
| `enigma.bilbo.lego.com/...` | 404/405 | Crypto/key services, needs `x-api-key`  |
| `rango.bilbo.lego.com/...`  | 404/405 | Element/tag services, needs `x-api-key` |


The Enigma service has endpoints like `CreateSpkitBundle` and `SharedKey` that may be involved in key provisioning for BrickNet or ASIC authentication. Access requires authentication.

## Decryption attempts so far

### Grain-128A keystream verification (`mac_capture/lib/grain_experiments.ex`)

- Correct IV extraction from bytes 5-16 of each tag
- Known plaintext keystream constraints verified against 3 ship tags (30/30 checks pass)
- Key candidate search with ~50 derived keys — no match (key is in ASIC silicon)

### Prior AES-CCM attempts (now known to target wrong cipher)

These targeted AES-CCM, which is used for BrickNet, not tags:

- ~1,100 candidate 16-byte keys extracted from firmware binaries
- 10 CCM nonce strategies (embedded, UID-derived, header-derived, fixed zeros, etc.)
- Nonce lengths: 7, 8, 10, 11, 12, 13 bytes; MAC lengths: 4, 8, 16 bytes
- Result: no valid decryptions — expected, since AES-CCM is not the tag cipher

### Other ciphers tested (all negative)

- Single-byte XOR, two-byte repeating XOR
- TEA / XTEA, SPECK / SIMON
- RC4
- AES-ECB / AES-CBC / AES-CTR / AES-CFB / AES-OFB

### SAT solver attempts (by node-smartplay)

- z3 (general-purpose SMT): timed out at >64 init rounds
- CryptoMiniSat (crypto-optimized, native XOR clauses): ~90K variables, killed after 2+ hours
- Conclusion: full 256-round Grain-128A resists SAT solvers even with 320 bits of constraint

## Key recovery options

Since the key is in the DA000001-01 ASIC silicon:

1. **SPI bus sniffing** — Capture ASIC→EM9305 traffic during tag reads to obtain decrypted plaintext directly. Most practical hardware approach. Doesn't give the key but confirms plaintext structure.
2. **Guess-and-determine attack** — ~2^64 complexity, theoretically feasible on a cloud GPU cluster over weeks/months. Uses the 320-bit keystream constraint.
3. **Hardware side-channel** — Power/EM analysis of the ASIC during tag reads. The 256 init rounds leak information through power consumption patterns.
4. **Silicon decapping** — Destructive microscopy of the ASIC die to read the key from ROM/OTP. Expensive and requires specialized equipment.
5. **Community collaboration** — The key is global (all bricks, all tags). Anyone who extracts it from one ASIC recovers it for all.

**Not viable:**

- JTAG on the EM9305 — the tag decryption key is not in the EM9305
- Firmware analysis — the EM9305 never handles encrypted tag data
- Bilbo API interception — unlikely to yield the Grain-128A tag key (may yield BrickNet/ASIC-auth keys)

## What works without the key

**Byte-perfect cloning** — Since all tags of the same type have identical encrypted content, and the smart brick reads data (not UID), copying the raw bytes to a blank writable tag produces a functional clone. No decryption needed.

See [cloning-guide.md](cloning-guide.md) for the practical cloning workflow.