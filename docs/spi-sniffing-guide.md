# SPI Bus Sniffing: Capturing Decrypted Tag Plaintext

## Goal

Capture the **decrypted TLV plaintext** that the DA000001-01 ASIC sends to the EM9305 over SPI during tag reads. This bypasses the Grain-128A encryption entirely — we get the plaintext without knowing the key.

## Why this is the most practical hardware approach

- The ASIC decrypts tags internally and deposits structured TLV data into EM9305 registers via SPI
- The EM9305 never sees encrypted tag data — the SPI bus carries plaintext
- A logic analyzer on the SPI lines captures everything the firmware processes
- No key extraction, no cryptanalysis, no silicon decapping required

## What it gives us

1. **Confirmed plaintext structure** — validate the TLV model from node-smartplay
2. **Exact content identity bytes** for every tag we scan
3. **Full keystream** for any tag: `keystream[i] = ciphertext[i] XOR plaintext[i]`, since we know the ciphertext from tag dumps
4. **More known-plaintext constraints** — currently 320 bits from 4 ship tags; SPI sniffing gives 100% plaintext for every scanned tag

Combined with the raw ciphertext (already captured), full plaintext gives us the complete keystream, which — with enough tags — provides massive constraint on the 128-bit Grain-128A key.

## Hardware architecture

The ASIC is memory-mapped into the EM9305's address space. Communication uses two register ranges:

| Range | Purpose |
| --- | --- |
| `0xF01800`–`0xF01860` | SPI/DMA control — command trigger, status, data buffer config |
| `0xF04000`–`0xF04BFF` | Tag/coil operations — command registers, anti-collision, FIFO, results |

The SPI driver (firmware `0x32304`–`0x326D0`) uses a 3-state DMA-based protocol:
- **State 0 (COMPLETE):** Transfer finished, data available for EM9305 to read
- **State 1 (ACTIVE):** DMA in progress, firmware spin-waits on `0xF0180C` bit 0
- **State 2 (IDLE):** Ready for new transfer; write 1 to `0xF01800` to initiate

After a tag read, copy functions at `0x69944`–`0x699E2` transfer **4 × 20-byte tag data blocks** from the ASIC result buffer into RAM. This is where the decrypted TLV data lands.

## What to look for on the bus

### Tag read sequence

1. EM9305 writes to `0xF04400` (RF_ENABLE = 4 for tag scan)
2. EM9305 writes command word `0x93C` to `0xF04008` (TAG_CMD) — this is an ASIC-internal opcode that triggers ISO 15693 inventory + read
3. ASIC performs NFC read and Grain-128A decryption internally (not visible on SPI)
4. ASIC fires interrupt (bit 21 = tag data ready)
5. EM9305 reads tag status from `0xF04054`, then reads result data via DMA
6. **The DMA transfer carries decrypted TLV plaintext** — this is the capture target

### Expected plaintext format

Per HARDWARE.md, the ASIC deposits a response starting with a flag byte:

```
Tag Response (from ASIC via SPI):
┌──────────────────────────────────┐
│ Flag Byte (1 byte)               │  Bit 0 = error, bit 3 = format variant
├──────────────────────────────────┤
│ UID (variable, 6-8 bytes)        │  Two parsing paths based on flag bit 3
├──────────────────────────────────┤
│ TLV Container (type 0x22)        │  Decrypted tag payload as sub-records
│   ├─ Identity block (7 bytes)    │  {content_lo:u32, content_hi:u16, type_byte:u8}
│   ├─ Timer ref (8 bytes)         │  Resource reference record
│   ├─ Button ref (8 bytes)        │  Resource reference record
│   └─ NPM ref (8 bytes)          │  Optional resource reference record
└──────────────────────────────────┘
```

## Equipment needed

### Option A: Logic analyzer (recommended)

- **Saleae Logic 8** or **Logic Pro 16** — easiest option, has a built-in SPI decoder
- **DSLogic Plus** — cheaper alternative with adequate sample rates
- Minimum 25 MHz sample rate (SPI clock is likely 1-8 MHz based on DMA transfer sizes)
- Thin gauge wire (30 AWG) or micro-grabbers for probe attachment

### Option B: Low-cost alternative

- **Raspberry Pi Pico** running PIO-based SPI sniffer firmware (e.g. `pico-spi-sniffer` or custom PIO program)
- **Bus Pirate v5** in SPI sniff mode
- Either works but has lower bandwidth and less robust timing than a dedicated logic analyzer

### Probing software

- **Saleae Logic 2** — if using Saleae hardware; built-in SPI analyzer
- **PulseView / sigrok** — open-source, works with DSLogic, Bus Pirate, and many analyzers; has SPI decoder
- **Custom script** — for the Pico approach, decode in Python/Elixir from raw capture

## Physical setup

### 1. Open the smart brick

The brick PCB has the EM9305 and DA000001-01 ASIC as separate packages. You need access to the SPI lines between them. Per the [Reddit teardown](https://www.reddit.com/r/LegoSmartBrick/comments/1rkkojk/i_disassembled_a_smart_brick/), the brick can be opened by removing screws under the battery compartment.

### 2. Identify the SPI lines

You need 4 signals:
- **SCK** (clock)
- **MOSI** (EM9305 → ASIC, master out)
- **MISO** (ASIC → EM9305, master in) — **this carries decrypted tag data**
- **CS** (chip select)

Plus **GND** reference.

The EM9305 is the SPI master. Decrypted tag data flows on **MISO** (ASIC to EM9305). If the PCB traces are not obvious, start by probing near the EM9305 package — look for 4 closely-spaced signals going to the ASIC.

### 3. Attach probes

- Solder thin wires to test pads or directly to SPI trace vias
- Use micro-grabbers on exposed pins/pads if available
- Ensure short wire runs to minimize signal integrity issues
- Connect GND from the analyzer to the brick's ground plane

### 4. Configure the analyzer

- SPI mode: likely Mode 0 (CPOL=0, CPHA=0) — start here, adjust if data looks garbled
- Bit order: MSB first (standard for EM Microelectronic)
- Sample rate: 4× the SPI clock minimum; 10× preferred
- Trigger on CS falling edge to capture complete transactions

## Capture procedure

1. Power on the brick (batteries in, button pressed)
2. Start recording on the logic analyzer
3. Present a tag to the brick — wait for recognition (LED response)
4. Stop recording
5. Decode the SPI transaction

### What to look for in the capture

1. **Write to 0xF04400 = 0x04** — RF enable for tag scan
2. **Write to 0xF04008 = 0x93C** — tag read command
3. **DMA read burst after interrupt** — 14 × 32-bit words (56 bytes) copied from `0xF01810+`
4. **The 80-byte block at the end** — 4 × 20-byte tag data blocks copied by functions at `0x69944`–`0x699E2`

The 80-byte region is the decrypted tag content. Extract it and compare against the known TLV structure.

## Validation

After capturing what you believe is decrypted plaintext:

1. **XOR with known ciphertext** to derive keystream
2. **Compare keystream against the 40 known keystream bytes** from `GrainExperiments.@ship_keystream` — all 40 should match
3. **Feed the key into `Grain128a.keystream/3`** — if you have enough plaintext and can perform key recovery from the keystream, verify it decrypts all tags correctly
4. **Check TLV structure** — the identity record should be 7 bytes with recognizable content IDs

## Potential complications

- **Memory-mapped, not bit-banged:** The ASIC may be accessed through the EM9305's internal bus fabric rather than external SPI pins. In this case, the SPI signals may not be available on external PCB traces — the communication could be entirely on-die or on-package. If so, a logic analyzer on external pins won't work and you'd need to intercept the EM9305's internal memory reads (much harder).
- **DMA transfers:** The EM9305 uses DMA (via `0xF01814`) for SPI data, with 512-byte transfer blocks. The DMA controller handles the actual data movement, so you need to capture the full burst, not just individual register reads.
- **Encrypted SPI:** It's possible (but unlikely) that the ASIC encrypts the SPI transfer itself. The ASIC-auth key at `0xF04084` might encrypt the data channel. If captured data looks random/high-entropy, this may be the case.
- **ASIC link requirement:** The ASIC link status at `0xF0383B` must have bits 0-1 = 3 (link established) before data is accepted. If the ASIC doesn't establish a link (e.g. due to probe loading), captures will be empty.

## Next steps after capture

1. **Verify TLV structure** against the node-smartplay model for all 15 known tag types
2. **Compute full keystream** for each tag (ciphertext XOR plaintext)
3. **Feed constraints into Grain-128A key search** — with full keystream for multiple tags (all sharing the same key), the key is uniquely determined and the constraint is massive
4. **Attempt key recovery** via guess-and-determine or algebraic methods with the full keystream
5. **If key recovered:** verify by decrypting tags without SPI sniffing (pure software)
