# RAGE9 `script.rpf` Format Specification

*License: `MIT OR Apache-2.0` — Clean-room format specification.*

## 1. Archive & Nested RPF9 Layout (`script.rpf`, 4,358,960 bytes)

`script.rpf` is a top-level `9FPR` (RPF9) archive containing **2** nested `9FPR` sub-archives and **1,057** plain 16-byte-aligned `zlib` streams that stitch into **1,013** logical entries:

| File Offset | Size | Magic / Type | Details |
|---|---|---|---|
| `0x000000` | `0x260` | `9FPR` (Top RPF9) | `toc_end = 0x260`, `names_size = 0x80`, `entries = 2`, `key_id = 0xc0a92754`, `flags = 0x00090f01`, `level = 3` |
| `0x001000` | `0x480` | `9FPR` (Sub-RPF9 #1) | `toc_end = 0x480`, `names_size = 0x40`, `entries = 2`, `key_id = 0x5a5b4c6f`, `flags = 0x00090f01`, `level = 7` |
| `0x001480` | `334,688 B` | Encrypted entry #1 | High-entropy (`7.988` bits/byte) opaque block inside Sub-RPF9 #1 (`0x001480..0x052d80`) |
| `0x053000` | `2,702,384 B` (inflated) | **Serialised Object Graph** | Sub-RPF9 #1 entry #2: **42** contiguous 64 KiB `zlib` streams (`0x053000..0x0c3b50`), followed by a 64-byte trailer (`0x0c3b50..0x0c3b90`) |
| `0x0c4000` | `0x11f10` | `9FPR` (Sub-RPF9 #2) | `toc_end = 0x11f10`, `names_size = 0x62b0`, `entries = 1,012`, `key_id = 0xda72573e`, `flags = 0x00090f02`, `level = 6` |
| `0x0d6000` | `3,477,872 B` (inflated) | **1,012 `PSIN` DOM Trees** | **1,015** `zlib` streams (`0x0d6000..0x421780`: 1,009 single-chunk + 3 two-chunk `PSIN` files) |
| `0x422000` | `25,392 B` | Opaque tail | High-entropy (`7.994` bits/byte) block at `0x422000..0x428330` |

**Decoding Coverage:** **1,057 / 1,057 (100.0%)** `zlib` streams (**1 / 1** Serialised Object Graph + **1,012 / 1,012** `PSIN` documents) decode and pass all structural invariants with zero failures.

---

## 2. RAGE9 `PSIN` (PSO v122) Container & Section Framing

Every `PSIN` file in `script.rpf` consists of **7** contiguous sections with **big-endian** 8-byte section headers (`[u8; 4] tag`, `u32_be total_section_len_including_8B_header`) and **little-endian** section bodies:

```
PSIN -> LSCH -> LENM -> LSNS -> LGID -> LRSC -> CHKS
```

### 2.1 `LRSC` (80 bytes — `0DRP` Type `0x7a` Resource Header)

| Offset | Type | Meaning |
|---|---|---|
| `0x00` | `[u8; 4]` | `"0DRP"` (`PRD0` little-endian magic) |
| `0x04` | `u32_le` | `0x0000007a` (v122 self-describing PSO/meta version) |
| `0x10` | `u32_le` | `root_block_index` (**1-based** index into the `PSIN` instance-block table) |
| `0x18..0x37` | `u64_le × 4` | `0xBBBBBBBBBBBBBBBB` runtime fixup pointer placeholders |
| `0x38` | `u16_le` | `struct_count` (number of struct schemas in `LSCH`) |
| `0x3A` | `u16_le` | `enum_count` (number of enum schemas in `LENM`) |
| `0x3C` | `u16_le` | `instance_block_count` (number of blocks in `PSIN`) |
| `0x3E` | `u16_le` | `0` |

### 2.2 `LSCH` (Struct & Member Schema Table)

Starts with `struct_count × 32`-byte struct descriptors, immediately followed by `sum(member_count) × 16`-byte member descriptors:

- **Struct Descriptor (32 B, LE):**
  - `+0x00`: `u32 name_hash`
  - `+0x04`: `u32 signature`
  - `+0x08`: `u32 flags` (`0x200` or `0x300`)
  - `+0x0C`: `u32 0`
  - `+0x10`: `u64 0xAAAAAAAAAAAAAAAA` (members pointer placeholder)
  - `+0x18`: `u32 struct_size` (bytes)
  - `+0x1C`: `u16 0`
  - `+0x1E`: `u16 member_count`
- **Member Descriptor (16 B, LE):**
  - `+0x00`: `u32 name_hash` (`0x00000100` = anonymous element schema for the following `0x5c` array member; otherwise case-sensitive JOAAT of field name)
  - `+0x04`: `u32 byte_offset`
  - `+0x08`: `u8 field_type` (`0x01` = bool, `0x05` = struct, `0x11` = u8, `0x13` = u16, `0x14` = s32/f32-bits, `0x15` = u32, `0x16` = u64, `0x44` = string, `0x4a` = JOAAT hash, `0x5c` = `atArray`, `0x60` = u8 enum)
  - `+0x09`: `u8 sub_type`
  - `+0x0A`: `u16 reference` (for `0x5c` arrays: index of the anonymous element member descriptor)
  - `+0x0C`: `u32 extra` (struct hash for `0x05`, enum hash for `0x60`)

### 2.3 `LENM` (Enum Schema Table)

Starts with `enum_count × 24`-byte enum descriptors (`{u32 name_hash, u32 signature, u64 0xEEEEEEEEEEEEEEEE, u32 value_count, u32 0}`), followed by `sum(value_count) × 16`-byte value entries (`{u64 enum_int_value, u64 value_name_hash}`).

### 2.4 `PSIN` (Instance Block Table & 16-Byte-Aligned Payloads)

- Starts at file offset `0x08` (`PSIN` payload `+0x00`) with `instance_block_count × 16`-byte block headers:
  - `+0x00`: `u32 type_hash` (struct `name_hash`, or primitive type code such as `0x16` for a `u64` pool)
  - `+0x04`: `u32 byte_size`
  - `+0x08`: `u64 0xAAAAAAAAAAAAAAAA`
- Padded with `0x70` (`'p'`) or `0x00` to the next **16-byte file boundary** (`file_off = align16(8 + instance_block_count * 16)`).
- Every block `i` (`1..=instance_block_count`) begins on a **16-byte file boundary** (`psin_payload_offset = file_off - 8`), occupies `byte_size` bytes, and is padded to the next 16-byte file boundary (`file_off = align16(file_off + byte_size)`).
- **Pool/Block Reference Encoding (`u64`):**
  - Bits `0..11` (`ref & 0xFFF`): **1-based** target block index.
  - Bits `20..63` (`ref >> 20`): byte offset inside the target block.

### 2.5 `LSNS`, `LGID`, and `CHKS`

- **`LSNS`**: 12-byte little-endian header `{u32 count = 1, u32 flags = 0x0101, u32 tail_len = section_payload_len - 12}`, followed by `tail_len` bytes (16-byte aligned, Shannon entropy `~7.9` bits/byte — obfuscated non-final string table).
- **`LGID`**: empty (`0` bytes payload) in all 1,012 `script.rpf` entries.
- **`CHKS`**: 12-byte big-endian payload `{u32_be total_file_size, u32_be checksum, [u8; 4] "zppp"}` (`0x7a` + `"ppp"`).

---

## 3. Compiled Binary-XML Script-Data DOM Schema (`0xde396fe2`)

All **1,012** `PSIN` documents in `script.rpf` share a single 4-struct, 1-enum schema representing a compiled hierarchical XML/DOM script-data tree (**20,379** nodes, **63,288** attributes, **7,929** 3D vectors, **13,440** 64-bit hashes):

### 3.1 Root Document Struct (`0xde396fe2`, size `0x50` B)

Contains five `0x5c` (`{u32 count, u32 capacity, u64 pool_ref}`) arrays:

| Offset | Field Hash | Resolved JOAAT Name | Element Type | Total Across 1,012 Files |
|---|---|---|---|---|
| `+0x00` | `0x749dbb9e` | **`attributes`** | `Struct 0x85b4c631` (16 B) | `63,288` |
| `+0x10` | `0x5c2411e5` | *(inline strings)* | `string` (type `0x44`) | `0` |
| `+0x20` | `0xd54b8545` | *(3D vectors)* | `Struct 0xaeb623d8` (12 B) | `7,929` |
| `+0x30` | `0x4880f687` | *(64-bit hash pool)* | `u64` (type `0x16`) | `13,440` |
| `+0x40` | `0x2260b8be` | **`dataNodes`** | `Struct 0x01393259` (16 B) | `20,379` |

### 3.2 Tree Node Struct (`0x01393259`, size `0x10` B)

| Offset | Type | Field Hash | Resolved JOAAT Name | Meaning |
|---|---|---|---|---|
| `+0x00` | `u32` | `0xe6e17f14` | **`name`** | Node tag JOAAT hash (node 0 is always `0xc090afad` = **`"root"`**; common child tag `0x1aecde4d` = **`"tag"`**) |
| `+0x04` | `u16` | `0xd89231bd` | **`parentIndex`** | Parent node index (`0xFFFF` for root) |
| `+0x06` | `u16` | `0x01296aed` | **`childIndex`** | First child node index (`0xFFFF` if leaf) |
| `+0x08` | `u16` | `0x881bf649` | **`siblingIndex`** | Next sibling node index (`0xFFFF` if last) |
| `+0x0A` | `u16` | `0xf33047d9` | **`previousSiblingIndex`** | Previous sibling node index (`0xFFFF` if first) |
| `+0x0C` | `u16` | `0x03341d59` | **`attributeStart`** | Start index in `attributes` (`0xFFFF` when `attributeCount == 0`) |
| `+0x0E` | `u8` | `0x79661755` | **`attributeCount`** | Number of contiguous attributes belonging to this node |
| `+0x0F` | `bool` | `0x31a7c9f6` | *(valid flag)* | Always `1` (`true`) |

### 3.3 Attribute Struct (`0x85b4c631`, size `0x10` B) & Enum `0x649ecf8e`

| Offset | Type | Field Hash | Resolved JOAAT Name | Meaning |
|---|---|---|---|---|
| `+0x00` | `u32` | `0xe6e17f14` | **`name`** | Attribute key JOAAT hash (e.g. `0x1b60404d` = **`"id"`**) |
| `+0x04` | `u32` | `0x817ed7a4` | **`valueHash`** | JOAAT hash of the authored string representation |
| `+0x08` | `u32` | `0x93bab68e` | *(raw value / index)* | Interpreted according to enum `+0x0C` |
| `+0x0C` | `u8` | `0x2a8e416f` | *(value type enum)* | Enum `0x649ecf8e` (`0..5`, see below) |
| `+0x0D` | `bool` | `0x31a7c9f6` | *(valid flag)* | Always `1` (`true`) |

**Enum `0x649ecf8e` Value Types:**
- `0` (`0x665e1b60`): **String Index** into `+0x10` string pool (`0` occurrences in retail `script.rpf`).
- `1` (`0x7f1ebdfc`): **Vector3 Index** (`0..vectors.len()`) into `+0x20` (`Struct 0xaeb623d8`: 3 × `f32` bitcast as `s32` fields **`x`** = `0x9303a5e5`, **`y`** = `0x80950108`, **`z`** = `0xb6606c9e`; `13,257` occurrences, 100% in-bounds).
- `2` (`0xd685d68f`): **Float32** (IEEE-754 `f32::from_bits(raw_val)`; `15,277` occurrences).
- `3` (`0x2339eeb0`): **Int32** (`raw_val as i32`; `14,739` occurrences).
- `4` (`0x3d39b587`): **Boolean** (`0` = `false` with `valueHash = 0xfe25ef42`, `1` = `true` with `valueHash = 0xb2f35c25`; `10` occurrences).
- `5` (`0xa038df91`): **U64 / StringHash64 Index** (`0..u64_table.len()`) into `+0x30` (`20,005` occurrences, 100% in-bounds).

---

## 4. Serialised Object Graph (`0x053000`, 2,702,384 bytes)

Stitched from 42 contiguous `zlib` streams (`#0..#41`), this binary is a self-contained typed object forest:

- **Header (`0x00..0x28`):** all zero except `u32_le record_count = 30,683` (`0x77db`) at `+0x14`.
- **Offset Table (`0x28..0x3bf00`):** `30,683 × u64_le` strictly ascending 16-byte-aligned record start offsets (`offsets[0] = align16(0x28 + record_count * 8) = 0x3bf00`).
- **Records (`0x3bf00..0x293c30`):** tile the remainder of the file with zero gaps:
  - `+0x00`: `u32 root_id` (non-zero JOAAT hash on the **483** unreferenced root records; `0` on internal child records).
  - `+0x04`: `u32 0`.
  - `+0x08`: `u64 type_hash` (**67** distinct values: 66 object schemas + array schema `0x14`).
  - **Array Schema (`type_hash == 0x14`, 10,294 records):** `+0x10` = `u32 count`, `+0x14` = `u32 count` (duplicated), `+0x18` = `u32 element_stride`; record byte size is `align16(0x30 + count * element_stride)` across 100% of array records.
  - **Tagged Pointers (30,200 pointers):** at 8-byte-aligned offsets `>= +0x10`, any 8-byte word `{u32_le target_plus_8, u32_le 0x71717171}` is a pointer to the record at byte offset `target_plus_8 - 8`. Every non-root record has in-degree 1, forming **483** disjoint trees of max depth 9 covering all **30,683 / 30,683 (100%)** records.
