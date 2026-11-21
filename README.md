# `rage9-re` — Clean-Room RAGE9 `script.rpf` & `anim.rpf` Decoder / Inspector

**License:** `MIT OR Apache-2.0` (dual-licensed, clean-room implementation with **zero** game bytes or asset dumps committed).

`rage9-re` provides complete Rust and Python parsers, validators, disassemblers, and exporters for the two RAGE9 archives in GTA VI (`1.0.2.1`):

1. **`script.rpf` (4.35 MB — 1,057 / 1,057 zlib streams = 100.0% decoded):**
   - **Nested RPF9 (`9FPR`) Container Scanner & 16-Byte-Aligned Zlib Carver/Stitcher**
   - **RAGE9 `PSIN` (PSO v122) Full Schema & Block Decoder** (`PSIN -> LSCH -> LENM -> LSNS -> LGID -> LRSC -> CHKS`)
   - **Compiled Binary-XML Script-Data DOM Tree Reconstructor** (`0xde396fe2` root struct, **1,012 / 1,012** files, **20,379** `dataNodes`, **63,288** typed `attributes`, **7,929** 3D `vectors`, **13,440** 64-bit hashes) with XML/JSON output
   - **Serialised Object Graph Disassembler** (`2,702,384` B, **30,683 / 30,683** records, **10,294** `0x14` array records, **30,200** `0x71717171`-tagged pointers, **483** root object trees)
2. **`anim.rpf` (4.4 GB — 100% of sampled `crClipDictionary` & `crAnimation` blocks decoded):**
   - **`crClipDictionary`, `crClip`, `crAnimDictionary`, `crAnimation`, and `crAnimSequence` Parser**
   - **All 7 Active RAGE9 Animation Channel Codecs:**
     - `Class 0`: Static Quaternion (`3 × f32` -> `w = sqrt(1 - x² - y² - z²)`)
     - `Class 1`: Static Vector3 (`3 × f32`)
     - `Class 2`: Static Float (`1 × f32`)
     - `Class 4`: Per-Frame Quantized Float (`12 B` header + LSB-first frame bitstream)
     - `Class 5`: Indirect Quantized Float Lookup Table (`20 B + 4*w2` LUT + LSB-first frame index bits)
     - `Class 7`: Reconstructed Quaternion Component (in-place insertion of `r = sqrt(1 - a² - b² - c²)` at component `k = slot & 3`)
     - `Class 8`: 4-Component Quaternion Normalization (`q /= |q|`)
     - `Class 10`: 64-Frame Superblock + 8-Lane SIMD Transposed 2nd-Order ZigZag Delta Curve (**21,084 / 21,084 = 100.0%** exact superblock bit-offset & anchor match!)
   - **glTF 2.0 (`.glb`) & JSON Animation Exporter** with resolved humanoid biped bone names (`skel_root`, `skel_pelvis`, `skel_spine0..3`, `skel_l/r_hand`, `skel_l/r_foot`, `ik_*`, `ph_*`)

## Quick Start

### Rust CLI & Tests

```bash
cargo test
cargo run --release -- inspect-script /path/to/script.rpf --dump-xml 0 --dump-objgraph 0
cargo run --release -- inspect-anim /path/to/anim.rpf --export-glb /tmp/rage9-re-work/sample.glb
```

### Python Tests

```bash
pytest -v
python3 -m unittest discover -s tests -v
```

## Specifications

- [`docs/SCRIPT_FORMAT.md`](docs/SCRIPT_FORMAT.md) — `script.rpf`, `PSIN` PSO v122, Compiled Binary-XML DOM Tree, and `0x71717171` Serialised Object Graph specification.
- [`docs/ANIM_FORMAT.md`](docs/ANIM_FORMAT.md) — `anim.rpf`, `crClipDictionary`, `crAnimation`, and `crAnimSequence` (Classes 0, 1, 2, 4, 5, 7, 8, 10) specification.
