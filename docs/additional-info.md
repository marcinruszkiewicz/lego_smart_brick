# Smart Brick resources

- https://blog.adafruit.com/2026/03/06/some-lego-smart-brick-ble-reverse-engineering/
- https://github.com/nathankellenicki/node-smartplay/tree/main — Node.js smart brick library, includes HARDWARE.md with tag dumps
- https://www.reddit.com/r/LegoSmartBrick/comments/1rkkojk/i_disassembled_a_smart_brick/
- https://www.heise.de/en/background/Lego-Smart-Play-Patent-applications-and-FCC-documents-reveal-the-technology-11135038.html?seite=all

# Smart tags resources

- https://www.youtube.com/shorts/kbI0hHGysUM — Vader tag payload video

# NFC chip datasheet

- EM4233 (EM Microelectronic) — the actual chip used in LEGO smart tags (IC ref 0x17). ISO 15693 compliant, 2k-bit EEPROM (264 bytes = 66 blocks × 4 bytes), 96-bit crypto engine, 32-bit password protection.
- Manufacturer code 0x16 in the UID = EM Microelectronic (not NXP as initially assumed).

# Backend

- LEGO "Bilbo" platform: `aup.bilbo.lego.com` (health), `enigma.bilbo.lego.com` (crypto/key services), `rango.bilbo.lego.com` (element/tag services). Functional endpoints require `x-api-key`.
- SmartAssist app: Unity/IL2CPP. Communicates with Bilbo services for tag verification and key provisioning.
