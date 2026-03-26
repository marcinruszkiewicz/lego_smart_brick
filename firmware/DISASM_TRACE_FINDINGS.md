# Firmware Disassembly Trace - AES-CCM Key Loading Analysis

> **Correction (2026-03):** The AES-CCM functions traced below are used for **BrickNet PAwR session encryption** and **EM9305↔ASIC mutual authentication** — **not** NFC tag decryption. Tag decryption uses **Grain-128A** (ISO/IEC 29167-13), handled entirely by the DA000001-01 ASIC. The EM9305 never sees encrypted tag data. See [docs/encryption-analysis.md](../docs/encryption-analysis.md).

## Summary

The AES-128-CCM key at hardware register `0x808904` is used for **BrickNet communication and ASIC mutual authentication**. It is **NOT** the NFC tag decryption key (which is most likely a Grain-128A key stored in the DA000001-01 ASIC silicon). The key is loaded into the AES crypto engine at runtime by reading this register.

## Key Findings

### 1. AES is Hardware-Accelerated

- No AES S-box found in the firmware binary
- The AES crypto engine is accessed through memory-mapped registers at `0x808800`-`0x8089FF`
- Key register: `0x808904`
- Status registers: `0x808825`, `0x808826`, `0x808838`
- Data/config registers: `0x80881C`, `0x808824`, `0x808890`, `0x8088A0`, `0x8088AC`

### 2. Crypto Initialization Function (0x03CA00)

The key loading sequence:

```
mov_s r0, 0x808904    ; source: AES key hardware register
mov_s r1, 0x80884c    ; dest: crypto engine parameter register  
mov_s r2, 4           ; parameter
bl.d  0x319f0         ; delayed branch to key-load function
mov_s r3, 0x10        ; r3 = 16 → AES-128 key size (set in delay slot)
```

This call reads 16 bytes from HW key register `0x808904` into the crypto engine at `0x80884c`.

### 3. Tag Security Verification Flow

String references found in the firmware (with 2-byte module/level prefix):

```
AES-CCM context create failed Result={}    (flash 0x375092)
AES_CCM_DecryptAndMAC failed Result={}     (flash 0x375484)
AES_CCM_GetMAC failed Result={}            (flash 0x375808)
AES_CCM MAC verification failed            (flash 0x375AD1)
Tag security verification passed           (flash 0x375B1C)
Unsupported tag security format={}         (flash 0x375106)
Invalid tag security info length={}        (flash 0x374B46)
Tag security information not present       (flash 0x374455)
```

### 4. Key Functions Identified


| Address  | Role            | Notes                                            |
| -------- | --------------- | ------------------------------------------------ |
| 0x03CA00 | Crypto init     | Loads AES key from HW, sets up crypto engine     |
| 0x03C984 | Tag slot config | Initializes 4 tag slot types (R/S/T/U)           |
| 0x0251CC | Tag slot mgmt   | Switch on slot type, configures crypto HW        |
| 0x025C50 | Error handler   | Handles AES-CCM failures, logs to 0x4B7B0        |
| 0x025718 | Tag data proc   | Most complex: 12 HW registers, 11 flash refs     |
| 0x03E67C | Tag reader      | 9 HW registers including 0x808904                |
| 0x02EB98 | Tag slot query  | Called with type IDs 0x52-0x55                   |
| 0x02EC50 | Config loader   | Loads code/config from flash addresses           |
| 0x04B7B0 | Log function    | Printf-style: `log(level, severity, str, param)` |


### 5. Tag Slot Types

The firmware manages 4 tag slot types identified by ASCII codes:

- `0x52` = 'R' (likely Read)
- `0x53` = 'S' (likely Security/Sign)
- `0x54` = 'T' (likely Tag)
- `0x55` = 'U' (likely Update/User)

### 6. RKEy Marker

Found at binary offset `0x04E0F2` (flash `0x3540F2`). The marker is embedded in code, not a data section. Three different variants exist across 9 firmware versions. Not directly referenced by any code — it may be metadata or a build marker.

## Implications

### For BrickNet / ASIC authentication (what this trace covers)

1. The AES-CCM key at `0x808904` is for BrickNet PAwR and EM9305↔ASIC mutual auth.
2. Key size: 16 bytes (AES-128) — confirmed by `mov_s r3, 0x10`.
3. During ASIC init, the EM9305 also copies a 16-byte key from config struct `0x80DCE4+0x26` (populated from ROFS config) to ASIC register `0xF04084`.
4. Extracting this key (via JTAG on the EM9305 or register `0x808904`) would yield the BrickNet/ASIC-auth key, not the tag decryption key.

### For NFC tag decryption (NOT covered by this trace)

1. Tag encryption uses **Grain-128A** (128-bit key, 96-bit IV), handled by the DA000001-01 ASIC.
2. The Grain-128A key is in the ASIC silicon — not accessible from the EM9305.
3. JTAG on the EM9305 will NOT yield the tag decryption key.
4. See [docs/encryption-analysis.md](../docs/encryption-analysis.md) for tag key recovery options (SPI sniffing, guess-and-determine, side-channel, silicon decapping).

## Hardware Register Map (Partial)

```
0x808800-0x808803  Status/state registers
0x808804-0x808807  Counter/accumulator
0x808810           Configuration
0x808814           Mode selector
0x80881C-0x80881F  Tag slot configuration
0x808820-0x80882C  Tag data buffer / pointers
0x808830-0x808832  Tag metadata
0x808838-0x808848  Timing / position data
0x80884C           Crypto engine key destination
0x808890-0x8088A0  Tag payload buffers
0x8088AC           Tag processing register
0x8088F0-0x8088FA  Extended status
0x808900           Crypto state machine state
0x808904           AES key hardware register (SOURCE)
0x808924           Crypto mode selector
```

