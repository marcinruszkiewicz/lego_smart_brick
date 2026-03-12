# Manual analysis: tag data path and TLV

How to confirm the TLV layout (type_id @ 0, content_len @ 2, event magic @ 4) from the firmware disassembly.

## 1. What you need

- **Extracted firmware:** `extracted/<version>/code.bin`
- **Disassembly:** `disassembly/<version>/disasm.txt` (from `disassemble.py`)
- **Flash base:** `0x306000` (code.bin offset 0 = flash 0x306000)

Pick one version that has `tag_message_parser` in code.bin (e.g. **fw_v1.119.0**).

## 2. Find who references `tag_message_parser`

The string lives at a **flash address** = `FLASH_BASE + offset_in_code.bin`.

- For fw_v1.119.0, offset of `tag_message_parser` is `0x6cad7` → flash **0x372ad7**.

In the disassembly, search for that address. ARC often loads it in two parts (e.g. high/low 16 bits) or as a single 24/32-bit immediate. Search for:

- `372ad7` or `372a d7` (with space)
- `0037 2ad7` (common in `mov_s rN, 0x...`)

```bash
grep -n "372ad7\|372a d7\|0037 2ad7" disassembly/fw_v1.119.0/disasm.txt
```

Each hit is a potential **caller** of code that uses the parser (e.g. logging or a table of module names). The actual parser logic is in the same binary but may not reference the string; you’re looking for functions that *do* reference it (e.g. error paths or init).

## 3. Analyze the tag data processing function (0x25718)

From [DISASM_TRACE_FINDINGS.md](DISASM_TRACE_FINDINGS.md), **0x25718** is the main “tag data processing” function (most complex, many HW regs and string refs).

**3.1 Dump the function**

- In `disasm.txt`, find the line whose address is `25718` (e.g. `25718:	enter_s	...`).
- Read from that line until the next `enter_s` or `leave_s`/`j_s [blink]` that ends the function (or cap at ~300 lines).

**3.2 List all calls**

- Every `bl` / `bl.d` is a call. In objdump output the target is often on the same line after `;`, e.g. `bl.d	112720	;410fc`.
- Collect those targets (e.g. 0x410fc, 0x2ec14, 0x3ed1c, …). Those are **callees**.

**3.3 Decide which callees touch “decrypted” data**

- Some callees will be crypto (AES-CCM, HW regs 0x8088xx), some will be helpers (memcpy, log).
- After the crypto call that does “decrypt and verify”, the firmware will work with the **plaintext buffer**. The next call that takes a **pointer to that buffer** is a good candidate for “parse TLV”.
- In the trace we already see 0x25718 calls **0x410fc** (with buffers) and **0x2ec14**. Inspect 0x410fc and 0x2ec14: do they take a pointer and then load from offset 0, 2, 4?

## 4. What to look for (TLV layout)

In any function that receives a pointer to the decrypted payload:

- **Bytes 0–1 (type_id, LE):**  
  `ldh rX,[rY,0]` or `ld_s` from `[rY,0]` (halfword or word at offset 0).
- **Bytes 2–3 (content length, LE):**  
  `ldh rX,[rY,2]` or load from `[rY,2]`.
- **Bytes 4–7 (event magic, 32-bit LE):**  
  `ld_s rX,[rY,4]` or two halfword loads from 4 and 6, then compare:
  - Identity: **0xA7E24ED1**
  - Item: **0x0BBDA113**

So: search for small offsets **0, 2, 4** (and 6) from a base register in loads/stores, and for **cmp** (or equivalent) with **0xa7e24ed1** or **0x0bbda113**. ARC may load 32-bit constants in two 16-bit halves (e.g. `mov_s r0, 0x4ed1` and `mov_s r1, 0xa7e2` then combine), so also look for **0x4ed1**, **0xa7e2**, **0xa113**, **0x0bbd** in isolation if they appear in a comparison context.

## 5. Scripted help

Run from `firmware/`:

```bash
python3 analyze_tag_path.py fw_v1.119.0
```

This will:

- Resolve the flash address of the `tag_message_parser` string.
- Find xrefs to that address in disasm.
- Dump the function at **0x25718** and list its **bl**/`bl.d` targets.
- Optionally dump the first N lines of each callee so you can search for offset-0/2/4 loads and magic comparisons by hand.

Then you can open `disassembly/fw_v1.119.0/disasm.txt` at the reported line numbers and follow the logic.

## 6. Summary

| Step | Action |
|------|--------|
| 1 | Choose a version with `tag_message_parser` (e.g. fw_v1.119.0). |
| 2 | Find xrefs to the parser string (flash 0x372ad7 or equivalent). |
| 3 | Dump function at **0x25718**, list all call targets. |
| 4 | In callees that take a payload pointer, look for loads at offsets 0, 2, 4 (and 6) and for comparisons with 0xA7E24ED1 / 0x0BBDA113. |
| 5 | If you see that pattern, the TLV layout is confirmed from firmware. |

---

## 7. Findings (fw_v1.119.0)

From `analyze_tag_path.py` output:

### 0xfe14 — TLV-like layout (type_id @ 0, content_len @ 2, value @ 4)

- `ldh_s r0,[r0,0]` — halfword at **offset 0** (type_id).
- `ldh_s r0,[r14,0x2]` — halfword at **offset 2** (content length).
- `ld_s r1,[r14,0x4]` — word at **offset 4** (candidate for event magic).
- Comparison: `brne.nt r0,r1` (compares with value at offset 4).
- Bounds checks using the length at offset 2 (`brhs.nt r0,0x801`, `brhs.nt r0,0x1fb9`), then advance by length + padding (`add r0,r16,0x3`, `bmskn`, `add_s r13,r13,0x8`), consistent with walking TLV entries.

This matches the expected decrypted layout: **bytes 0–1 type_id, 2–3 content_len, 4–7 magic/value**.

### 0x3ed1c — Structure with halfwords at 4, 6, 8, 0xa

- `ldh_s r2,[r0,0x4]`, `ldh_s r3,[r0,0x6]`, `ldh_s r2,[r0,0x8]`, `ldh_s r0,[r0,0xa]` — reads a record starting at offset 4 (e.g. first TLV payload or a nested structure). Supports the same general layout (important data at offset 4+).

### Conclusion

The firmware **confirms** a TLV-style layout with a 2-byte field at 0, 2-byte field at 2, and 4-byte (or longer) field at 4, in at least one path (0xfe14) used from the tag data processing flow. The exact constants 0xA7E24ED1 / 0x0BBDA113 have not been seen as immediates in this pass; the comparison at 0xfe14 may use a value in a register loaded elsewhere.

---

## 8. Confirming the magic constants (Identity / Item)

To **confirm the magic constants** (0xA7E24ED1 for Identity, 0x0BBDA113 for Item) from the firmware:

1. **Search for 4-byte literals** in `code.bin` and in **rofs_files/play** (LE and BE). Run:
   ```bash
   python3 find_magic_constants.py fw_v1.119.0
   ```
   The script also searches the disassembly for 32-bit immediates and 16-bit halves (0x4ed1, 0xa7e2, 0xa113, 0x0bbd) in `mov`/`ld`/`cmp` context. If the constants appear in the "1b. rofs_files/play" output, they are confirmed in the ROFS play file.

2. **If not found** (current outcome): the constants may be
   - in another segment (e.g. ROFS data), not in the extracted code.bin;
   - computed at runtime from the type_id at offset 0 (e.g. table index);
   - loaded via a different instruction encoding (e.g. PC-relative load from a literal pool the disassembler didn’t label).

3. **Trace the comparison at 0xfe14:** the value at `[r14,4]` is compared with the return value of the call to **0x12064** (with payload+8 and length). So the “expected” value may come from 0x12064 or its callees (e.g. 0x11ffc). Inspecting 0x12064 for a constant return (or a load from a table) could reveal the magic; so far 0x12064 delegates to 0x11ffc and other paths and does not show an obvious 0xA7E24ED1 / 0x0BBDA113 immediate.

**Bottom line:** the **layout** (type_id @ 0, content_len @ 2, magic @ 4) is confirmed from firmware; the **numeric values** 0xA7E24ED1 and 0x0BBDA113 are still taken from documentation until found in the binary or in a table. Those values (and the full event-type table) originate from [node-smartplay HARDWARE.md](https://github.com/nathankellenicki/node-smartplay/blob/main/notes/HARDWARE.md#tag-content-data), which cites debug strings (v0.46–v0.54) and disassembly of v0.72.1. Our extracted build (fw_v1.119.0) has ROFS version **0.46.0** (same content generation); the constants still do not appear as literals in our search, so they may have been inferred from control flow or a different build.

---

## 9. Version mapping: v1.119.0 → v2.29.1 (magic as anchor)

In **fw_v2.29.1** the magic constants appear as immediates in the disassembly. Use them to find the equivalents of the v1.119.0 tag path.

### Where the magics are in v2.29.1

| Address   | Instruction              | Constant      | Role in code |
|----------|---------------------------|---------------|--------------|
| **0x66cb0** | `mov_s r2, 0xa7e24ed1` | Identity      | Argument to call 0x50944 |
| **0x66cc8** | `mov_s r2, 0xa7e24ed1` | Identity      | Argument to same handler path |
| **0x66cf4** | `mov_s r2, 0xbbda113`  | Item          | Argument to call 0x509d8 |
| 0x66d12 | `mov_s r2, 0x812312dc`   | Play command  | Call 0x50c84 |
| 0x66d28 | `mov_s r2, 0x814a0d84`  | Distributed   | Call 0x50c84 |
| 0x66d3e | `mov_s r2, 0xe3b77171`   | Status/pos    | Call 0x50c04 |

All of these are inside **one function: 0x66c74** (starts at `enter_s [r13-r14,blink]` at 0x66c74). That function is an **event-type dispatcher**: it switches on an event type and calls the appropriate handler, passing the magic as `r2`.

### v1.119.0 → v2.29.1 mapping

| v1.119.0   | v2.29.1   | Notes |
|------------|-----------|--------|
| **0xfe14** | **0x66c74** (and callees) | **0xfe14** = TLV loop: load halfword @ 0, @ 2, word @ 4; compare @ 4 with magic (from 0x12064). In v2.29.1 the magic is **in the dispatcher** (0x66c74) and passed into **0x50944** (Identity) and **0x509d8** (Item). So 0x66c74 is the “event-type switch”; the actual TLV walk (load 0, 2, 4 and compare) is likely inside 0x50944 / 0x509d8 or their callees (e.g. 0x6cf44, 0x51058, 0x51318, 0x510f4). A candidate for “load type_id @ 0, content_len @ 2” in v2.29.1 is the function at **0x4142** (lines ~6203–6205): `ldh_s r14,[r12,0]` and `ldh_s r13,[r12,0x2]`. |
| **0x3ed1c** | Search for same pattern | **0x3ed1c** in v1.119.0: reads halfwords at offsets 4, 6, 8, 0xa from a buffer (`ldh_s` at 0x4, 0x6, 0x8, 0xa). In v2.29.1, search for a function that does `ldh_s` at [rN,4], [rN,6], [rN,8], [rN,0xa] in sequence (e.g. `grep -n "ldh_s.*0x4\|ldh_s.*0x6\|ldh_s.*0x8\|ldh_s.*0xa" disasm.txt` and inspect surrounding code). |

### Quick reference (v2.29.1)

- **Event dispatcher (has all event-type magics):** **0x66c74**
- **Identity handler (receives 0xa7e24ed1):** **0x50944**
- **Item handler (receives 0xbbda113):** **0x509d8**
- **TLV-style “type_id @ 0, content_len @ 2”:** candidate at **0x4142** (ldh at 0 and 2 from r12)
