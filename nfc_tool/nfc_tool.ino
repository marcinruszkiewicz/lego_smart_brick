/*
 * NFC ISO 15693 (Type 5) Reader/Writer - Export to Mac
 * Reads ISO 15693 tags via PN7150 and sends JSON over Serial (115200 baud).
 * Supports cloning: Mac sends CLONE: command, Arduino writes blocks to tag.
 * Mac side: use mac_capture Elixir app to capture, analyze, and clone.
 *
 * Board: Wemos D1 R32 (ESP32). PN7150 shield stacked or wired.
 *
 * Wemos D1 R32 pinout (Arduino Uno footprint when shield is stacked):
 *   I2C:  SDA = GPIO21 (A4),  SCL = GPIO22 (A5)
 *   IRQ  = GPIO12  (shield D11 — if init fails, try GPIO23)
 *   VEN  = GPIO14 (shield D13 — if init fails, try GPIO18)
 *   I2C address: 0x28
 *
 * If your shield uses different pins, change PN7150_IRQ and PN7150_VEN below.
 *
 * Serial protocol (Mac → Arduino):
 *   "CLONE:<hex>\n"  - Write blocks to detected tag. <hex> = concatenated
 *                      block data (e.g. "00A9010C012A7206..." for blocks
 *                      0,1,2,...). Each 8 hex chars = one 4-byte block.
 *   "READ\n"         - Read the tag (default behavior on detect).
 *
 * Serial protocol (Arduino → Mac):
 *   "WRITE_OK:<block>\n"   - Block written+verified successfully.
 *   "WRITE_FAIL:<block>\n" - Block write or verify failed.
 *   "WRITE_DONE:<ok>/<total>\n" - Clone complete summary.
 */

#include "Electroniccats_PN7150.h"

#define PN7150_IRQ  (12)   /* D11 on Uno-style shield */
#define PN7150_VEN  (14)  /* D13 on Uno-style shield */
#define PN7150_ADDR (0x28)

#define MAX_BLOCKS_ISO15693 128
#define SERIAL_BAUD 115200

/* Set to 0 to disable debug (only NFC15693: JSON lines for Mac capture). */
#define DEBUG_NFC 1

Electroniccats_PN7150 nfc(PN7150_IRQ, PN7150_VEN, PN7150_ADDR, PN7150);

static inline void printHexByte2(uint8_t v) {
  if (v <= 0x0F) Serial.print('0');
  Serial.print(v, HEX);
}

static inline void printHexBytes(const uint8_t* data, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) {
    printHexByte2(data[i]);
  }
}

static uint8_t s_respBuf[256];
static uint8_t s_respSize;

/* Clone mode: when set, write these blocks to the next detected tag. */
static bool     s_cloneMode = false;
static uint8_t  s_cloneData[512]; /* max 128 blocks × 4 bytes */
static uint16_t s_cloneLen = 0;   /* bytes in s_cloneData */

static uint8_t hexCharToNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0xFF;
}

/* Parse a hex string into s_cloneData. Returns byte count or 0 on error. */
static uint16_t parseHexString(const char* hex, uint16_t hexLen) {
  if (hexLen % 2 != 0) return 0;
  uint16_t byteLen = hexLen / 2;
  if (byteLen > sizeof(s_cloneData)) return 0;
  for (uint16_t i = 0; i < byteLen; i++) {
    uint8_t hi = hexCharToNibble(hex[i * 2]);
    uint8_t lo = hexCharToNibble(hex[i * 2 + 1]);
    if (hi == 0xFF || lo == 0xFF) return 0;
    s_cloneData[i] = (hi << 4) | lo;
  }
  return byteLen;
}

/*
 * GET SYSTEM INFORMATION (0x2B) — ISO 15693
 * Returns: info flags, UID, DSFID, AFI, memory size (block count + block size),
 *          and IC reference byte (identifies exact chip model).
 *
 * The PN7150 NCI layer strips the leading response-flag byte from the T5T
 * response, so s_respBuf[0] is already the info-flags byte.
 */
void readSystemInfo() {
  uint8_t cmd[] = { 0x02, 0x2B };
  s_respSize = sizeof(s_respBuf);
  delay(20);
  bool ok = nfc.readerTagCmd(cmd, sizeof(cmd), s_respBuf, &s_respSize);

#if DEBUG_NFC
  Serial.print(F("[DEBUG] SYSINFO ok="));
  Serial.print(ok);
  Serial.print(F(" size="));
  Serial.print(s_respSize);
  Serial.print(F(" raw="));
  printHexBytes(s_respBuf, s_respSize > 20 ? 20 : s_respSize);
  Serial.println();
#endif

  Serial.print(F("SYSINFO:"));
  if (s_respSize < 1) {
    Serial.println(F("{\"error\":\"no_response\"}"));
    return;
  }

  /*
   * The PN7150 may or may not strip the response-flag byte.
   * If s_respBuf[0] looks like info-flags (0x00-0x0F), treat it as stripped.
   * If it's 0x00 followed by info-flags, treat byte 0 as the response-flag.
   */
  uint8_t flags;
  uint8_t pos;
  if (s_respSize >= 2 && s_respBuf[0] == 0x00 && (s_respBuf[1] & 0xF0) == 0x00) {
    /* Response-flag byte present (0x00 = no error) */
    flags = s_respBuf[1];
    pos = 2;
  } else {
    /* Response-flag already stripped by NCI */
    flags = s_respBuf[0];
    pos = 1;
  }

  Serial.print(F("{\"flags\":\""));
  printHexByte2(flags);
  Serial.print(F("\""));

  /* Dump ALL raw bytes so we can analyze regardless of parsing */
  Serial.print(F(",\"raw\":\""));
  printHexBytes(s_respBuf, s_respSize);
  Serial.print(F("\""));

  /* UID (8 bytes) — always present in unaddressed GET SYSTEM INFORMATION */
  if (pos + 8 <= s_respSize) {
    Serial.print(F(",\"uid\":\""));
    printHexBytes(&s_respBuf[pos], 8);
    Serial.print(F("\""));
    pos += 8;
  }

  /* DSFID (1 byte) if bit 0 set */
  if ((flags & 0x01) && pos < s_respSize) {
    Serial.print(F(",\"dsfid\":\""));
    printHexByte2(s_respBuf[pos]);
    Serial.print(F("\""));
    pos++;
  }

  /* AFI (1 byte) if bit 1 set */
  if ((flags & 0x02) && pos < s_respSize) {
    Serial.print(F(",\"afi\":\""));
    printHexByte2(s_respBuf[pos]);
    Serial.print(F("\""));
    pos++;
  }

  /* Memory size (2 bytes: num_blocks-1 and block_size-1) if bit 2 set */
  if ((flags & 0x04) && pos + 1 < s_respSize) {
    uint8_t numBlocksM1 = s_respBuf[pos];
    uint8_t blockSizeM1 = s_respBuf[pos + 1];
    Serial.print(F(",\"num_blocks\":"));
    Serial.print(numBlocksM1 + 1);
    Serial.print(F(",\"block_size\":"));
    Serial.print(blockSizeM1 + 1);
    pos += 2;
  }

  /* IC reference (1 byte) if bit 3 set — identifies exact chip model */
  if ((flags & 0x08) && pos < s_respSize) {
    Serial.print(F(",\"ic_ref\":\""));
    printHexByte2(s_respBuf[pos]);
    Serial.print(F("\""));
    pos++;
  }

  Serial.println(F("}"));
}

/*
 * GET MULTIPLE BLOCK SECURITY STATUS (0x2C) — ISO 15693
 * Returns one security-status byte per block.
 * Bit 0 = lock bit (1=permanently locked).
 * We read in batches of 32 to stay within buffer limits.
 */
void readSecurityStatus(uint8_t startBlock, uint8_t count) {
  uint8_t cmd[] = { 0x02, 0x2C, startBlock, (uint8_t)(count - 1) };
  s_respSize = sizeof(s_respBuf);
  delay(20);
  bool ok = nfc.readerTagCmd(cmd, sizeof(cmd), s_respBuf, &s_respSize);

#if DEBUG_NFC
  Serial.print(F("[DEBUG] SECSTATUS ok="));
  Serial.print(ok);
  Serial.print(F(" size="));
  Serial.print(s_respSize);
  Serial.print(F(" raw="));
  printHexBytes(s_respBuf, s_respSize > 20 ? 20 : s_respSize);
  Serial.println();
#endif

  Serial.print(F("SECSTATUS:"));
  if (s_respSize < 2) {
    Serial.println(F("{\"error\":\"no_response\"}"));
    return;
  }

  /*
   * Response: [flag_byte] [status_byte_0] [status_byte_1] ...
   * PN7150 may strip the flag byte (same ambiguity as SYSINFO).
   * Detect: if first byte is 0x00 or 0x01 and remaining bytes are also 0x00/0x01,
   * the flag was likely stripped. Otherwise byte 0 is the flag.
   */
  uint8_t dataStart = 0;
  if (s_respBuf[0] == 0x00 && s_respSize > count) {
    dataStart = 1;  /* flag byte present */
  }

  Serial.print(F("{\"start\":"));
  Serial.print(startBlock);
  Serial.print(F(",\"count\":"));
  Serial.print(count);
  Serial.print(F(",\"status\":\""));
  uint8_t locked = 0;
  for (uint8_t i = 0; i < count && (dataStart + i) < s_respSize; i++) {
    uint8_t val = s_respBuf[dataStart + i];
    printHexByte2(val);
    if (val & 0x01) locked++;
  }
  Serial.print(F("\""));
  Serial.print(F(",\"locked_count\":"));
  Serial.print(locked);
  Serial.println(F("}"));
}

/*
 * WRITE SINGLE BLOCK (0x21) + read-back verify.
 * Writes 4-byte blocks from s_cloneData to the tag.
 */
void writeTagFromCloneData() {
  uint16_t numBlocks = s_cloneLen / 4;
  uint16_t okCount = 0;

  Serial.print(F("WRITE_START:"));
  Serial.println(numBlocks);

  for (uint16_t blockNum = 0; blockNum < numBlocks; blockNum++) {
    uint8_t writeCmd[7];
    writeCmd[0] = 0x02;  /* flags: high data rate, unaddressed */
    writeCmd[1] = 0x21;  /* WRITE SINGLE BLOCK */
    writeCmd[2] = (uint8_t)blockNum;
    writeCmd[3] = s_cloneData[blockNum * 4 + 0];
    writeCmd[4] = s_cloneData[blockNum * 4 + 1];
    writeCmd[5] = s_cloneData[blockNum * 4 + 2];
    writeCmd[6] = s_cloneData[blockNum * 4 + 3];

    s_respSize = sizeof(s_respBuf);
    delay(20);
    nfc.readerTagCmd(writeCmd, sizeof(writeCmd), s_respBuf, &s_respSize);

    /* Read back to verify */
    delay(15);
    uint8_t readCmd[] = { 0x02, 0x20, (uint8_t)blockNum };
    s_respSize = sizeof(s_respBuf);
    nfc.readerTagCmd(readCmd, sizeof(readCmd), s_respBuf, &s_respSize);

    bool verified = false;
    if (s_respSize >= 5) {
      uint8_t off = (s_respBuf[0] == 0x00) ? 1 : 0;
      if (s_respSize - off >= 4) {
        verified = (s_respBuf[off + 0] == s_cloneData[blockNum * 4 + 0] &&
                    s_respBuf[off + 1] == s_cloneData[blockNum * 4 + 1] &&
                    s_respBuf[off + 2] == s_cloneData[blockNum * 4 + 2] &&
                    s_respBuf[off + 3] == s_cloneData[blockNum * 4 + 3]);
      }
    }

    if (verified) {
      Serial.print(F("WRITE_OK:"));
      Serial.println(blockNum);
      okCount++;
    } else {
      Serial.print(F("WRITE_FAIL:"));
      Serial.print(blockNum);
      Serial.print(F(" expected="));
      printHexByte2(s_cloneData[blockNum * 4 + 0]);
      printHexByte2(s_cloneData[blockNum * 4 + 1]);
      printHexByte2(s_cloneData[blockNum * 4 + 2]);
      printHexByte2(s_cloneData[blockNum * 4 + 3]);
      Serial.print(F(" got="));
      if (s_respSize >= 5) {
        uint8_t off = (s_respBuf[0] == 0x00) ? 1 : 0;
        for (uint8_t i = 0; i < 4 && (off + i) < s_respSize; i++) {
          printHexByte2(s_respBuf[off + i]);
        }
      } else {
        Serial.print(F("no_read"));
      }
      Serial.println();
    }
  }

  Serial.print(F("WRITE_DONE:"));
  Serial.print(okCount);
  Serial.print(F("/"));
  Serial.println(numBlocks);
}

void emitTagJson() {
  const uint8_t* id = nfc.remoteDevice.getID();
  uint8_t afi = nfc.remoteDevice.getAFI();
  uint8_t dsfid = nfc.remoteDevice.getDSFID();
  uint8_t* Resp = s_respBuf;
  uint8_t RespSize = 0;

  /* Query system info first for chip identification */
  readSystemInfo();

  /* Query security status in batches of 32 */
  readSecurityStatus(0, 32);
  readSecurityStatus(32, 32);

  Serial.print(F("NFC15693:{\"uid\":\""));
  printHexBytes(id, 8);
  Serial.print(F("\",\"afi\":\""));
  printHexByte2(afi);
  Serial.print(F("\",\"dsfid\":\""));
  printHexByte2(dsfid);
  Serial.print(F("\",\"blocks\":["));

  bool first = true;
  uint8_t lastPayload[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
  uint8_t lastPayloadLen = 0;
  uint8_t sameCount = 0;
  bool stoppedSameBlock = false;
  const uint8_t SAME_THRESHOLD = 3;  /* Stop after this many identical filler blocks in a row. */

  for (uint8_t blockNum = 0; blockNum < MAX_BLOCKS_ISO15693; blockNum++) {
    uint8_t ReadBlock[] = { 0x02, 0x20, blockNum };
    s_respSize = sizeof(s_respBuf);
    delay(15);  /* Short delay between block reads so tag/reader can keep up. */
    bool ok = nfc.readerTagCmd(ReadBlock, sizeof(ReadBlock), Resp, &s_respSize);
    RespSize = s_respSize;
    if (RespSize < 2) {
#if DEBUG_NFC
      Serial.print(F("[DEBUG] Stop at block "));
      Serial.print(blockNum);
      Serial.print(F(" RespSize="));
      Serial.println(RespSize);
#endif
      break;
    }

    uint8_t payloadLen = RespSize - 1;
    if (payloadLen > 4) payloadLen = 4;

    /* Stop only when the 2-byte filler (0x00 0x01) is repeated 3x — not on "00000000". */
    if (payloadLen == lastPayloadLen) {
      bool same = true;
      for (uint8_t i = 0; i < payloadLen; i++) {
        if (Resp[1 + i] != lastPayload[i]) { same = false; break; }
      }
      if (same) {
        sameCount++;
        if (sameCount >= SAME_THRESHOLD) {
          /* Only stop on the real past-end filler (2 bytes 0x00 0x01), not on zero blocks. */
          bool isFiller = (payloadLen == 2 && Resp[1] == 0x00 && Resp[2] == 0x01);
          if (isFiller) {
            stoppedSameBlock = true;
            break;
          }
          sameCount = 0;  /* reset and keep reading (e.g. more "00000000" blocks). */
        }
      } else {
        sameCount = 1;
      }
    } else {
      sameCount = 1;
    }
    for (uint8_t i = 0; i < payloadLen; i++) lastPayload[i] = Resp[1 + i];
    lastPayloadLen = payloadLen;

    if (!first) Serial.print(',');
    Serial.print('\"');
    for (uint8_t i = 0; i < payloadLen; i++) {
      printHexByte2(Resp[1 + i]);
    }
    Serial.print('\"');
    first = false;
  }

  Serial.println(F("]}"));
#if DEBUG_NFC
  if (stoppedSameBlock) {
    Serial.println(F("[DEBUG] Stopped: same block repeated 3x (past end of tag)."));
  }
#endif
}

static char s_serialBuf[1200]; /* enough for CLONE: + 512 bytes as hex + \n */
static uint16_t s_serialPos = 0;

void checkSerialCommands() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (s_serialPos > 0) {
        s_serialBuf[s_serialPos] = '\0';

        if (strncmp(s_serialBuf, "CLONE:", 6) == 0) {
          char* hex = s_serialBuf + 6;
          uint16_t hexLen = s_serialPos - 6;
          uint16_t byteLen = parseHexString(hex, hexLen);
          if (byteLen > 0 && byteLen % 4 == 0) {
            s_cloneLen = byteLen;
            s_cloneMode = true;
            Serial.print(F("CLONE_READY:"));
            Serial.print(byteLen / 4);
            Serial.println(F(" blocks loaded. Present a blank tag."));
          } else {
            Serial.println(F("CLONE_ERR:Invalid hex data (must be multiple of 8 hex chars)"));
          }
        } else if (strncmp(s_serialBuf, "READ", 4) == 0) {
          s_cloneMode = false;
          Serial.println(F("MODE:read"));
        } else if (strncmp(s_serialBuf, "CANCEL", 6) == 0) {
          s_cloneMode = false;
          s_cloneLen = 0;
          Serial.println(F("MODE:read (clone cancelled)"));
        }
        s_serialPos = 0;
      }
    } else if (s_serialPos < sizeof(s_serialBuf) - 1) {
      s_serialBuf[s_serialPos++] = c;
    }
  }
}

void setup() {
  Serial.begin(SERIAL_BAUD);
  while (!Serial) { ; }

  Serial.println(F("NFC ISO15693 Reader/Writer (115200 baud)"));
  Serial.println(F("Commands: CLONE:<hex>, READ, CANCEL"));

  if (nfc.connectNCI()) {
    Serial.println(F("Error: NCI init failed. Check wiring (IRQ/VEN/I2C)."));
    Serial.println(F("Wemos D1 R32: IRQ=GPIO2, VEN=GPIO14, SDA=21, SCL=22."));
    for (;;) { ; }
  }
  if (nfc.configureSettings()) {
    Serial.println(F("Error: configureSettings failed."));
    for (;;) { ; }
  }
  if (nfc.configMode()) {
    Serial.println(F("Error: configMode failed."));
    for (;;) { ; }
  }
  nfc.startDiscovery();
  Serial.println(F("Waiting for ISO15693 tag..."));
}

void loop() {
  checkSerialCommands();

  if (!nfc.isTagDetected(500)) {
    nfc.reset();
    delay(500);
    return;
  }

#if DEBUG_NFC
  Serial.print(F("[DEBUG] Tag detected, protocol="));
  Serial.print((int)nfc.remoteDevice.getProtocol());
  Serial.print(F(" tech="));
  Serial.println((int)nfc.remoteDevice.getModeTech());
#endif

  if (nfc.remoteDevice.getProtocol() != nfc.protocol.ISO15693 ||
      nfc.remoteDevice.getModeTech() != nfc.tech.PASSIVE_15693) {
    Serial.println(F("Not Type 5 (ISO15693) - ignoring."));
    nfc.waitForTagRemoval();
    nfc.reset();
    delay(500);
    return;
  }

  if (s_cloneMode) {
    Serial.println(F("[CLONE] Writing to tag..."));
    writeTagFromCloneData();
    s_cloneMode = false;
    s_cloneLen = 0;
    Serial.println(F("MODE:read (clone complete, back to read mode)"));
  } else {
#if DEBUG_NFC
    Serial.println(F("[DEBUG] Type 5 - reading blocks..."));
#endif
    emitTagJson();
  }

  if (nfc.remoteDevice.hasMoreTags()) {
    nfc.activateNextTagDiscovery();
  } else {
    Serial.println(F("Remove the card."));
    nfc.waitForTagRemoval();
  }

  nfc.reset();
  Serial.println(F("Waiting for ISO15693 tag..."));
  delay(500);
}
