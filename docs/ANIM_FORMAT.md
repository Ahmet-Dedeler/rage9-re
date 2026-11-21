# RAGE9 `anim.rpf` Format Specification

*License: `MIT OR Apache-2.0` — Clean-room format specification.*

## 1. Archive Overview (`anim.rpf`, 4,407,626,384 bytes)

- **RPF9 Header (`0x00..0x40`):** magic `9FPR`, `toc_end = 0x4660`, `names_size = 0x2a90`, `entries = 265` (top-level sub-archives/packs), `key_id = 0xd98004d5`, `flags = 0x00090f02`, `level = 6`.
- **Two Resource Families:**
  1. **Low Region (`0x00005000 .. ~0x15000000`):** `0DRP` type `0x7a` (v122 self-describing meta resources) storing cutscene, scenario, and clip-set metadata.
  2. **Main Region (`~0x15000000 .. 0x106B70000`):** RAGE9 **`crClipDictionary`** resources (starting at `4 KiB + 0x10` boundaries, easily identified by `0x50xxxxxx` system pointers at `+0x08`, `+0x38`, `+0x48`, `+0x70` and all-zero bytes at `+0x10..+0x37`).

---

## 2. `crClipDictionary`, `crClip`, and `crAnimDictionary`

All pointers use standard RAGE9 64-bit system-page addressing (`0x50000000 | byte_offset`).

### 2.1 `crClipDictionary` Header (`0x00..0x88`)

| Offset | Type | Meaning |
|---|---|---|
| `+0x00` | `u64` | `0` (vtable placeholder) |
| `+0x08` | `ptr` | Page-map pointer (`0x50xxxxxx`) |
| `+0x10..+0x37` | `[u8; 40]` | All zeros (`0x00`) |
| `+0x38` | `ptr` | Dictionary name C-string (e.g. `"ambient@ai_react@breakouts@..."`) |
| `+0x40` | `u16, u16, u32` | `name_len`, `name_cap` (`name_len + 1`), `1` |
| `+0x48` | `ptr` | `atMap<u32, pgRef<crClip>>` bucket pointer array (`bucket_count × 8` B) |
| `+0x50` | `u16` | `bucket_count` |
| `+0x58` | `u16` | `clip_count` |
| `+0x68` | `u32, u32` | Dictionary JOAAT hash, `2` |
| `+0x70` | `ptr` | `atArray` of `crAnimDictionary` entries (`{ptr anim_dict, u32 hash, u32 1, ...}`) |
| `+0x78` | `u16, u16` | `anim_dict_count` (typically `1`), `anim_dict_cap` |

Each `atMap` bucket points to a singly-linked list of 24-byte nodes: `{u32 key_hash, u32 0, ptr target_object, ptr next_node}`.

### 2.2 `crClip` (`crClipAnimations`, size `0x88` B)

| Offset | Type | Meaning |
|---|---|---|
| `+0x10` | `u32` | Clip type (`1` = `crClipAnimations`) |
| `+0x28` | `ptr` | Clip path C-string (e.g. `"pack:/breakout_quick_backleft.clip"`) |
| `+0x30` | `u16, u16` | `name_len`, `name_cap` |
| `+0x40` | `ptr` | Clip property map (`crProperties`) |
| `+0x48` | `ptr` | Clip tag table (`crTag` intervals) |
| `+0x58` | `u32, u32` | `clip_hash`, `parent_dict_hash` |
| `+0x68` | `ptr` | Pointer to 16-byte array header `{ptr bindings, u16 count, u16 cap, u32 0}` |
| `+0x78` | `f32` | Clip duration in seconds |

**Multi-Rate Animation Slice Bindings (`bindings`, stride `0x38` B):**
RAGE9 batches multiple clips into shared `.anim` containers split by sampling rate (commonly **3** `.anim` files per clip dictionary: **30 Hz** high-rate primary skeleton tracks, **15 Hz** medium-rate tracks, and **10 Hz** low-rate tracks). Each `crClip` binds `count` (usually 3) animation slices:
- `+0x00`: `ptr -> crAnimation`
- `+0x08`: `u32 anim_hash`
- `+0x28`: `f32 start_time` (seconds inside `crAnimation`)
- `+0x2C`: `f32 end_time` (seconds inside `crAnimation`, where `(end_time - start_time) / rate == clip.duration`)
- `+0x30`: `f32 rate` (playback speed multiplier, ~`1.0`)

### 2.3 `crAnimDictionary` (`0x00..0x90`)

Mirrors `crClipDictionary`:
- `+0x38`: `ptr` to dictionary name string (`"<clip_dict_name>-0"`).
- `+0x48`: `ptr` to `atMap<u32, pgRef<crAnimation>>` buckets (`+0x50` = `u16 bucket_count`, `+0x58` = `u16 anim_count`).

---

## 3. `crAnimation` & Track Descriptors (`0x70` bytes)

| Offset | Type | Meaning |
|---|---|---|
| `+0x18` | `ptr` | Parent `crAnimDictionary` |
| `+0x20` | `u16, u16` | `flags` (`0x0140` / `0x0150`), `0` |
| `+0x24` | `u16` | `num_frames` (total frames across the animation) |
| `+0x26` | `u16` | `seq_frames` (frame limit per `crAnimSequence` block) |
| `+0x28` | `f32` | `duration` (seconds; frame rate = `(num_frames - 1) / duration`, typically 30, 15, or 10 Hz) |
| `+0x2C` | `u32` | `signature` |
| `+0x30` | `ptr` | Animation name C-string (e.g. `"pack:/biped_q5@biped@0@30_0.anim"`) |
| `+0x48` | `u32` | `max_block_size` (`0x20 + block.payload_size`) |
| `+0x50` | `ptr, u16, u16` | `atArray<ptr<crAnimSequence>> blocks` (multi-block animations overlap by 1 boundary frame per split: `sum(blk.num_frames) - (block_count - 1) == num_frames`) |
| `+0x60` | `ptr, u16, u16` | `atArray<crAnimTrackDesc> tracks` (12 bytes per track) |

### 3.1 Track Descriptor (`crAnimTrackDesc`, 12 bytes)

| Offset | Type | Meaning |
|---|---|---|
| `+0x00` | `u32` | `bone_id`: **JOAAT of lowercase bone name** (`0x00000000` = root/mover, `0x6686685c` = `"skel_root"`, `0x8133de19` = `"skel_pelvis"`, `0x41e5d6a1` = `"skel_spine0"`, etc.), sorted ascending per track group |
| `+0x04` | `u32` | `track_type`: **JOAAT of lowercase track semantic** (`0x98e1750c` = `"bonerotation"`, `0xf791a95f` = `"bonetranslation"`, `0x2deefadd` = `"genericcontrol"`, `0xf5c3a5b6` = `"generictranslation"`, `0x6ddef121` = `"cameratranslation"`, `0x60d0644c` = `"firstpersoncameraweight"`) |
| `+0x08` | `u32` | `value_type`: `0` = **Quaternion** (`Vec4V`, 4 float slots), `2` = **Vector3** (`Vec3V`, 3 active float slots + 1 padding slot), `4` = **Float** (1 active float slot + 3 padding slots) |

**SIMD Slot Allocation Rule:** Every track `ti` (`0..tracks.len()`) is allocated **4 consecutive float slots** `4*ti .. 4*ti + 3` (`x, y, z, w`), giving `4 * tracks.len()` total slots per frame.

---

## 4. `crAnimSequence` Block Layout & The 11 Channel Classes

### 4.1 Block Header (`0x20` bytes)

| Offset | Type | Meaning |
|---|---|---|
| `+0x00` | `u32` | `signature` |
| `+0x04` | `u32` | `payload_size` (total block size from `+0x00` is `0x20 + payload_size`) |
| `+0x08` | `u32` | `0` |
| `+0x0C` | `u32` | `data_off` (byte size of the channel descriptor region `+0x20 .. +0x20 + data_off`; per-frame bitstream starts at **`+0x20 + data_off`**) |
| `+0x10` | `u32` | `index_end_off` (byte offset from `+0x00` where the 11-class index table ends) |
| `+0x14` | `u16` | `version` (always `2`) |
| `+0x16` | `u16` | `num_frames` in this block |
| `+0x18` | `u16` | `frame_stride` (bytes per frame in the per-frame bitstream: `ceil((bits_per_frame + sum(class5.idx_bits)) / 32) * 4`) |
| `+0x1A` | `u16` | Static/setup word count |
| `+0x1C` | `u16` | `bits_per_frame` (exact sum of `num_bits` across all Class-4 channels) |
| `+0x1E` | `u8` | `num_classes` (always `11`) |
| `+0x1F` | `u8` | `fast_seek_flags` (`> 0` iff optional 6-byte fast-seek records follow `index_end_off .. 0x20 + payload_size`) |

### 4.2 Block Memory Map

```
+0x0000 .. +0x0020 : 32-byte crAnimSequence Header
+0x0020 .. +0x0020 + data_off : Sequential Channel Descriptors (Class 0 -> Class 1 -> Class 2 -> Class 4 -> Class 5 -> Class 10)
+0x0020 + data_off .. +coff   : Per-Frame Bitstream (num_frames * frame_stride bytes; Class 4 bits [0..bpf], then Class 5 index bits)
+coff   .. +coff + 22         : 11 x u16_le class_counts[0..10] (where coff = 0x20 + data_off + num_frames * frame_stride)
+coff + 22 .. +index_end_off  : For each class ci with count = class_counts[ci] > 0:
                                `align4(count)` x u16_le target float-slot indices (padded with sentinel 4*num_tracks)
+index_end_off .. +0x20 + payload_size : Optional 6-byte fast-seek records `{u8 class_id, u8 sub_idx, u16 target_slot, u16 bit_offset}`
```

### 4.3 The Channel Classes (`0..10`)

| Class | Name | Descriptor Size | Decoding Rule |
|---|---|---|---|
| **0** | **Static Quaternion** | `12 B` (`3 × f32`) | Target slot `sl = 4 * track`. Reads `(x, y, z)`, reconstructs `w = sqrt(max(0, 1 - x² - y² - z²))`, writes constant `(x, y, z, w)` to `sl .. sl+3`. |
| **1** | **Static Vector3** | `12 B` (`3 × f32`) | Target slot `sl = 4 * track`. Writes constant `(x, y, z)` to `sl .. sl+2`. |
| **2** | **Static Float** | `4 B` (`f32`) | Writes constant `v` to target slot `sl`. |
| **4** | **Per-Frame Quantized Float** | `12 B` (`{u32 bits, f32 quantum, f32 offset}`) | In frame `f`, reads `bits` unsigned integer `u` LSB-first from the frame bitstream and outputs `offset + u * quantum` to slot `sl`. |
| **5** | **Indirect Quantized Float (LUT)** | `20 + 4 * lut_dwords B` (`{u32 idx_bits, u32 val_bits, u32 lut_dwords, f32 quantum, f32 offset, u32 lut[lut_dwords]}`) | Unpacks `(lut_dwords * 32) / val_bits` LUT entries (`lut[k] = offset + u_k * quantum`, `val_bits` LSB-first). In frame `f`, reads an `idx_bits` index `idx` LSB-first from the frame bitstream (immediately after the `bits_per_frame` Class-4 bits) and outputs `lut[idx]`. |
| **7** | **Reconstructed Quaternion Component** | `0 B` (post-process) | Target slot `sl = base + k` (`base = 4 * track`, `k = sl & 3`). The 3 stored components live in `(base+0, base+1, base+2)` as `(a, b, c)`. Computes `r = sqrt(max(0, 1 - a² - b² - c²))` and **inserts `r` at index `k`** (`k=0 -> [r,a,b,c]`, `k=1 -> [a,r,b,c]`, `k=2 -> [a,b,r,c]`, `k=3 -> [a,b,c,r]`), then normalizes `q /= |q|`. |
| **8** | **4-Component Quaternion Normalize** | `0 B` (post-process) | Target slot `sl = 4 * track`. All 4 components `(x, y, z, w)` are explicitly stored in `sl .. sl+3`; normalizes `(x, y, z, w) /= sqrt(x² + y² + z² + w²)`. |
| **10** | **64-Frame Superblock 8-Lane 2nd-Order Delta Curve** | `4 * total_dwords B` | Self-contained random-access second-order delta-compressed curve (see §4.4 below). |
| *3, 6, 9* | *(Unused)* | `0 B` | Count is `0` across all sampled blocks. |

### 4.4 Class 10: 64-Frame Superblock + 8-Lane SIMD 2nd-Order ZigZag Delta Codec

Class 10 compresses smooth trajectories using **second-order integer differences (discrete acceleration)** Reset every **64 frames** (`n_super = ceil(num_frames / 64)` superblocks), with deltas transposed across **8 SIMD lanes** (`n_groups = ceil((num_frames - 1) / 8)` groups of 8 frames):

1. **16-Byte Header:**
   - `+0x00`: `u32 total_dwords` (total channel size = `total_dwords * 4` bytes)
   - `+0x04`: `u8 offset_bits` (`b4`: bit-width of each per-superblock lane bit-offset; `0` when all offsets are `0`)
   - `+0x05`: `u8 anchor_bits` (`b5`: bit-width of each per-superblock initial integer sample `anchors[sb]`)
   - `+0x06`: `u8 lane_dwords` (`b6`: 32-bit words per lane; the trailing `8 * b6` dwords hold 8 interleaved lanes `lane_words[slice * 8 + lane]`)
   - `+0x07`: `u8 0`
   - `+0x08`: `f32 quantum`
   - `+0x0C`: `f32 offset`
2. **Prefix Bitstream (`n_pref = total_dwords - 4 - 8 * b6` dwords at `+0x10`, read LSB-first):**
   - **Superblock Bit-Offsets (`n_super × b4` bits):** `offsets[sb]` equals the exact cumulative bit offset in each lane at superblock `sb` (`sum(runs[0 .. sb*8])`).
   - **Superblock Anchors (`n_super × b5` bits):** `anchors[sb]` is the exact integer value at frame `t = 64 * sb`.
   - **Group Unary Bit-Widths (`n_groups` unary codes):** starting at bit `n_super * (b4 + b5)`, each group `g` (`0..n_groups`) stores `bw = runs[g]` as `bw` zero bits followed by a `1` bit.
3. **8-Lane Delta Unpacking & 2nd-Order Integration:**
   - For each group `g` (`0..n_groups`) with bit-width `bw = runs[g]`, read `bw` bits from each lane `li = 0..7` at lane bit-offset `bp` (then `bp += bw`), and ZigZag-decode into signed acceleration `d[8*g + li] = (u >> 1) ^ -(u & 1)`.
   - For each 64-frame superblock `sb` (`0..n_super`), at frame `t0 = 64 * sb`:
     - Initialize `pos = anchors[sb]`, `vel = 0`, `int_val[t0] = pos`.
     - For `t = t0 + 1 .. min(num_frames, t0 + 64)`:
       ```
       vel += d[t - 1]
       pos += vel
       int_val[t] = pos
       ```
     - **Mathematical Ground-Truth Check:** continuing one more step (`t = t0 + 64`) lands on `pos == anchors[sb + 1]` with **zero error** across **21,084 / 21,084 (100.0%)** verified Class-10 channels!
   - Convert to float: `val[t] = offset + int_val[t] * quantum`.
