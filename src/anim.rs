// rage9-re by Ahmet Dedeler (https://github.com/Ahmet-Dedeler, https://ahmetdedeler.com)
// Source: https://github.com/Ahmet-Dedeler/rage9-re
// SPDX-License-Identifier: MIT OR Apache-2.0
// If you copy, vendor or port this file, keep this header and credit rage9-re in your README.
//! RAGE9 `anim.rpf` decoder (`crClipDictionary`, `crClip`, `crAnimDictionary`,
//! `crAnimation`, `crAnimSequence` channel codecs) and JSON / glTF 2.0 exporter.

use crate::rpf9::resolve_known_hash;
use std::collections::HashSet;

const MAX_ALLOC_SLOT_FLOATS: usize = 64 * 1024 * 1024; // 256 MiB cap against crafted OOM

#[inline]
fn u16_le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

#[inline]
fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[inline]
fn u64_le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[inline]
fn f32_le(b: &[u8], o: usize) -> f32 {
    f32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[inline]
pub fn sys_ptr(b: &[u8], o: usize) -> Option<usize> {
    if o.checked_add(8)? > b.len() {
        return None;
    }
    let v = u64_le(b, o);
    if (v >> 28) == 5 {
        let off = (v & 0x0fff_ffff) as usize;
        if off < b.len() {
            return Some(off);
        }
    }
    None
}

#[inline]
pub fn read_cstr(b: &[u8], off: usize) -> Option<String> {
    if off >= b.len() {
        return None;
    }
    let rel_end = b[off..].iter().position(|&c| c == 0)?;
    Some(String::from_utf8_lossy(&b[off..off + rel_end]).into_owned())
}

/// Read `0..=32` bits LSB-first from an arbitrary byte slice at `bit_offset`.
#[inline]
pub fn read_bits_le(bytes: &[u8], bit_offset: usize, num_bits: usize) -> u32 {
    if num_bits == 0 {
        return 0;
    }
    let byte_idx = bit_offset >> 3;
    let bit_shift = bit_offset & 7;
    let mut acc = 0u64;
    for i in 0..8 {
        if byte_idx + i < bytes.len() {
            acc |= (bytes[byte_idx + i] as u64) << (i * 8);
        }
    }
    let mask = if num_bits >= 32 {
        u32::MAX as u64
    } else {
        (1u64 << num_bits) - 1
    };
    ((acc >> bit_shift) & mask) as u32
}

/// Find 1-based bit length (index of highest set bit + 1) of a little-endian byte slice.
#[inline]
pub fn bit_length_le(bytes: &[u8]) -> usize {
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b != 0 {
            return i * 8 + (8 - b.leading_zeros() as usize);
        }
    }
    0
}

#[inline]
pub fn zigzag_decode(u: u32) -> i32 {
    ((u >> 1) as i32) ^ -((u & 1) as i32)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClipAnimBinding {
    pub anim_offset: usize,
    pub anim_hash: u32,
    pub start_time: f32,
    pub end_time: f32,
    pub rate: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CrClip {
    pub offset: usize,
    pub hash: u32,
    pub name: String,
    pub duration: f32,
    pub bindings: Vec<ClipAnimBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackValueType {
    Quaternion = 0,
    Vector3 = 2,
    Float = 4,
    Unknown = 255,
}

impl TrackValueType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Quaternion,
            2 => Self::Vector3,
            4 => Self::Float,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnimTrackDesc {
    pub bone_id: u32,
    pub track_type: u32,
    pub value_type: TrackValueType,
    pub raw_value_type: u32,
}

impl AnimTrackDesc {
    pub fn bone_name(&self) -> String {
        resolve_known_hash(self.bone_id)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("bone_{:08x}", self.bone_id))
    }

    pub fn track_type_name(&self) -> String {
        resolve_known_hash(self.track_type)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("type_{:08x}", self.track_type))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodedTrackFrames {
    Quaternions(Vec<[f32; 4]>), // [x, y, z, w] unit quaternions
    Vectors(Vec<[f32; 3]>),     // [x, y, z] translations
    Floats(Vec<f32>),           // scalar curve
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedAnimBlock {
    pub offset: usize,
    pub signature: u32,
    pub num_frames: usize,
    pub frame_stride: usize,
    pub bits_per_frame: usize,
    pub class_counts: [u16; 11],
    pub trailer_records: usize,
    pub class10_verified: usize,
    pub slot_frames: Vec<Vec<f32>>, // 4 * num_tracks slots, each of len num_frames
}

#[derive(Debug, Clone, PartialEq)]
pub struct CrAnimation {
    pub offset: usize,
    pub hash: u32,
    pub name: String,
    pub flags: u16,
    pub num_frames: usize,
    pub seq_frames: usize,
    pub duration: f32,
    pub signature: u32,
    pub max_block_size: u32,
    pub tracks: Vec<AnimTrackDesc>,
    pub blocks: Vec<DecodedAnimBlock>,
    pub track_frames: Vec<DecodedTrackFrames>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CrClipDictionary {
    pub name: String,
    pub anim_dict_name: String,
    pub clips: Vec<CrClip>,
    pub animations: Vec<CrAnimation>,
}

fn walk_at_map(b: &[u8], buckets_ptr: usize, bucket_count: usize) -> Vec<(u32, usize)> {
    let mut out = Vec::new();
    for bi in 0..bucket_count {
        let Some(slot_off) = bi.checked_mul(8).and_then(|d| buckets_ptr.checked_add(d)) else {
            break;
        };
        let mut node_opt = sys_ptr(b, slot_off);
        let mut guard = 0usize;
        while let Some(node) = node_opt {
            if node.checked_add(24).is_none_or(|e| e > b.len()) || guard > 4096 {
                break;
            }
            let h = u32_le(b, node);
            if let Some(val) = sys_ptr(b, node + 8) {
                out.push((h, val));
            }
            node_opt = sys_ptr(b, node + 16);
            guard += 1;
        }
    }
    out
}

/// Decode a RAGE9 Class-10 channel (64-frame superblock + 8-lane SIMD transposed 2nd-order ZigZag delta curve).
pub fn decode_class10_channel(
    num_frames: usize,
    raw: &[u8],
) -> Result<(Vec<f32>, bool, bool), String> {
    if raw.len() < 16 {
        return Err("Class 10 channel shorter than 16-byte header".into());
    }
    let dw = u32_le(raw, 0) as usize;
    let dw_bytes = dw
        .checked_mul(4)
        .ok_or_else(|| "Class 10 dword count overflow".to_string())?;
    if dw < 4 || dw_bytes > raw.len() {
        return Err("Class 10 dword count out of range".into());
    }
    let b4 = raw[4] as usize;
    let b5 = raw[5] as usize;
    let b6 = raw[6] as usize;
    if b4 > 32 || b5 > 32 {
        return Err(format!("Class 10 prefix bit widths out of range (b4={b4}, b5={b5})"));
    }
    let quantum = f32_le(raw, 8);
    let offset = f32_le(raw, 12);

    if 4 + 8 * b6 > dw {
        return Err("Class 10 lane dwords exceed total dwords".into());
    }
    let n_pref = dw - 4 - 8 * b6;
    let pref_bytes = &raw[16..16 + n_pref * 4];
    let lane_base = 16 + n_pref * 4;

    let mut lane_bytes = vec![vec![0u8; b6 * 4]; 8];
    for s in 0..b6 {
        for (li, lane) in lane_bytes.iter_mut().enumerate() {
            let w_off = lane_base + (s * 8 + li) * 4;
            lane[s * 4..s * 4 + 4].copy_from_slice(&raw[w_off..w_off + 4]);
        }
    }

    let n_super = num_frames.div_ceil(64);
    let mut offsets = Vec::with_capacity(n_super);
    for i in 0..n_super {
        offsets.push(read_bits_le(pref_bytes, i * b4, b4) as usize);
    }
    let mut anchors = Vec::with_capacity(n_super);
    let anchor_bit_base = n_super * b4;
    for i in 0..n_super {
        anchors.push(read_bits_le(pref_bytes, anchor_bit_base + i * b5, b5) as i32);
    }

    let skip = n_super * (b4 + b5);
    let top_bit = bit_length_le(pref_bytes);
    let n_groups = num_frames.saturating_sub(1).div_ceil(8);
    let mut runs = Vec::with_capacity(n_groups);
    let mut p = skip;
    while p < top_bit {
        let mut z = 0usize;
        while p < top_bit && read_bits_le(pref_bytes, p, 1) == 0 {
            z += 1;
            p += 1;
        }
        if p < top_bit {
            p += 1;
            runs.push(z);
        }
    }

    let mut cum_ok = runs.len() == n_groups;
    if cum_ok {
        for (sb, &expected_off) in offsets.iter().enumerate() {
            let c: usize = runs[..(sb * 8).min(runs.len())].iter().sum();
            if c != expected_off {
                cum_ok = false;
                break;
            }
        }
    }

    let mut deltas = Vec::with_capacity(runs.len().saturating_mul(8));
    let mut bp = 0usize;
    for &bw in &runs {
        if bw > 32 {
            return Err(format!("Class 10 delta bit width {bw} > 32"));
        }
        for lane in &lane_bytes {
            let u = read_bits_le(lane, bp, bw);
            deltas.push(zigzag_decode(u));
        }
        bp = bp.saturating_add(bw);
    }

    let mut ints = vec![0i32; num_frames];
    let mut anchor_ok = true;
    for sb in 0..n_super {
        let t0 = sb * 64;
        let mut cur_p = anchors[sb];
        let mut cur_v = 0i32;
        if t0 < num_frames {
            ints[t0] = cur_p;
        }
        let t_end = num_frames.min(t0 + 64);
        for (t, slot) in ints.iter_mut().enumerate().take(t_end).skip(t0 + 1) {
            let d = deltas.get(t - 1).copied().unwrap_or(0);
            cur_v = cur_v.wrapping_add(d);
            cur_p = cur_p.wrapping_add(cur_v);
            *slot = cur_p;
        }
        if sb + 1 < n_super {
            let d = deltas.get(t0 + 63).copied().unwrap_or(0);
            cur_v = cur_v.wrapping_add(d);
            cur_p = cur_p.wrapping_add(cur_v);
            if cur_p != anchors[sb + 1] {
                anchor_ok = false;
            }
        }
    }

    let floats = ints
        .into_iter()
        .map(|x| offset + (x as f32) * quantum)
        .collect();
    Ok((floats, cum_ok, anchor_ok))
}

impl DecodedAnimBlock {
    pub fn parse(b: &[u8], blk_off: usize, num_tracks: usize) -> Result<Self, String> {
        let hdr_end = blk_off
            .checked_add(0x20)
            .ok_or_else(|| "Anim block offset overflow".to_string())?;
        if hdr_end > b.len() {
            return Err("Anim block header out of bounds".into());
        }
        let signature = u32_le(b, blk_off);
        let u04 = u32_le(b, blk_off + 0x04) as usize;
        let data_off = u32_le(b, blk_off + 0x0c) as usize;
        let u10 = u32_le(b, blk_off + 0x10) as usize;
        let num_frames = u16_le(b, blk_off + 0x16) as usize;
        let frame_stride = u16_le(b, blk_off + 0x18) as usize;
        let bits_per_frame = u16_le(b, blk_off + 0x1c) as usize;
        let b1e = b[blk_off + 0x1e];
        if b1e != 11 {
            return Err(format!("Expected 11 channel classes, got {b1e}"));
        }

        let desc_end = 0x20usize
            .checked_add(data_off)
            .ok_or_else(|| "Anim block data_off overflow".to_string())?;
        let frame_bytes = num_frames
            .checked_mul(frame_stride)
            .ok_or_else(|| "Anim block frame_bytes overflow".to_string())?;
        let coff = desc_end
            .checked_add(frame_bytes)
            .ok_or_else(|| "Anim block coff overflow".to_string())?;
        let counts_end_abs = blk_off
            .checked_add(coff)
            .and_then(|v| v.checked_add(22))
            .ok_or_else(|| "Anim block tail counts overflow".to_string())?;
        let u10_abs = blk_off
            .checked_add(u10)
            .ok_or_else(|| "Anim block u10 overflow".to_string())?;
        if counts_end_abs > b.len() || u10_abs > b.len() || u10 < coff + 22 {
            return Err("Anim block tail counts out of bounds".into());
        }
        let mut class_counts = [0u16; 11];
        for (i, slot) in class_counts.iter_mut().enumerate() {
            *slot = u16_le(b, blk_off + coff + i * 2);
        }

        let mut ip = coff + 22;
        let mut idxs: Vec<Vec<usize>> = vec![Vec::new(); 11];
        for ci in 0..11 {
            let c = class_counts[ci] as usize;
            if c > 0 {
                let padded = (c + 3) & !3;
                let table_bytes = padded
                    .checked_mul(2)
                    .ok_or_else(|| "Channel index table size overflow".to_string())?;
                let next_ip = ip
                    .checked_add(table_bytes)
                    .ok_or_else(|| "Channel index table offset overflow".to_string())?;
                if next_ip > u10 {
                    return Err("Channel index table exceeds u10".into());
                }
                let mut list = Vec::with_capacity(c);
                for k in 0..c {
                    list.push(u16_le(b, blk_off + ip + k * 2) as usize);
                }
                idxs[ci] = list;
                ip = next_ip;
            }
        }
        if ip != u10 {
            return Err(format!("Tail index end 0x{ip:x} != u10 0x{u10:x}"));
        }

        let total_end = 0x20usize.saturating_add(u04);
        let trailer_bytes = total_end.saturating_sub(u10);
        let trailer_records = trailer_bytes / 6;

        let max_slot = idxs
            .iter()
            .flat_map(|v| v.iter().copied())
            .max()
            .unwrap_or(0);
        let track_slots = num_tracks
            .checked_mul(4)
            .ok_or_else(|| "Track slot count overflow".to_string())?;
        let idx_slots = max_slot
            .checked_add(4)
            .map(|v| v & !3)
            .ok_or_else(|| "Slot index overflow".to_string())?;
        let num_slots = track_slots.max(idx_slots);
        let total_floats = num_slots
            .checked_mul(num_frames)
            .ok_or_else(|| "Anim block slot buffer size overflow".to_string())?;
        if total_floats > MAX_ALLOC_SLOT_FLOATS {
            return Err(format!(
                "Anim block slot buffer too large ({num_slots} slots x {num_frames} frames)"
            ));
        }
        let mut slot_frames = vec![vec![0.0f32; num_frames]; num_slots];

        let mut pos = 0x20usize;
        let check_desc = |cur: usize, need: usize| -> Result<usize, String> {
            let next = cur
                .checked_add(need)
                .ok_or_else(|| "Channel descriptor offset overflow".to_string())?;
            if next > desc_end {
                return Err(format!(
                    "Channel descriptor at 0x{cur:x} (+{need}) exceeds data_off 0x{desc_end:x}"
                ));
            }
            Ok(next)
        };

        // Class 0: Static Quaternion (3 x f32 -> w = sqrt(max(0, 1 - x^2 - y^2 - z^2)))
        for &sl in &idxs[0] {
            let next = check_desc(pos, 12)?;
            let x = f32_le(b, blk_off + pos);
            let y = f32_le(b, blk_off + pos + 4);
            let z = f32_le(b, blk_off + pos + 8);
            pos = next;
            let w = (1.0f32 - (x * x + y * y + z * z)).max(0.0).sqrt();
            if sl + 3 < num_slots {
                slot_frames[sl].fill(x);
                slot_frames[sl + 1].fill(y);
                slot_frames[sl + 2].fill(z);
                slot_frames[sl + 3].fill(w);
            }
        }

        // Class 1: Static Vector3 (3 x f32)
        for &sl in &idxs[1] {
            let next = check_desc(pos, 12)?;
            let x = f32_le(b, blk_off + pos);
            let y = f32_le(b, blk_off + pos + 4);
            let z = f32_le(b, blk_off + pos + 8);
            pos = next;
            if sl + 2 < num_slots {
                slot_frames[sl].fill(x);
                slot_frames[sl + 1].fill(y);
                slot_frames[sl + 2].fill(z);
            }
        }

        // Class 2: Static Float (1 x f32)
        for &sl in &idxs[2] {
            let next = check_desc(pos, 4)?;
            let v = f32_le(b, blk_off + pos);
            pos = next;
            if sl < num_slots {
                slot_frames[sl].fill(v);
            }
        }

        // Class 4: Per-frame quantized float descriptors (12 bytes each)
        let mut q4 = Vec::with_capacity(idxs[4].len());
        let mut q4_bits_sum = 0usize;
        for _ in 0..idxs[4].len() {
            let next = check_desc(pos, 12)?;
            let nbits = u32_le(b, blk_off + pos) as usize;
            if nbits > 32 {
                return Err(format!("Class 4 nbits {nbits} > 32"));
            }
            let q = f32_le(b, blk_off + pos + 4);
            let off = f32_le(b, blk_off + pos + 8);
            pos = next;
            q4_bits_sum = q4_bits_sum
                .checked_add(nbits)
                .ok_or_else(|| "Class 4 bit sum overflow".to_string())?;
            q4.push((nbits, q, off));
        }
        if q4_bits_sum != bits_per_frame {
            return Err(format!(
                "Class 4 bit sum {q4_bits_sum} != header bpf {bits_per_frame}"
            ));
        }

        // Class 5: Indirect quantized float descriptors + LUT
        let mut c5 = Vec::with_capacity(idxs[5].len());
        let mut c5_bits_sum = 0usize;
        for _ in 0..idxs[5].len() {
            check_desc(pos, 20)?;
            let idx_bits = u32_le(b, blk_off + pos) as usize;
            let val_bits = u32_le(b, blk_off + pos + 4) as usize;
            let lut_dwords = u32_le(b, blk_off + pos + 8) as usize;
            if val_bits == 0 || val_bits > 32 {
                return Err(format!("Invalid Class 5 val_bits {val_bits}"));
            }
            if idx_bits > 32 {
                return Err(format!("Invalid Class 5 idx_bits {idx_bits}"));
            }
            let lut_bytes = lut_dwords
                .checked_mul(4)
                .ok_or_else(|| "Class 5 lut_dwords overflow".to_string())?;
            let total_need = 20usize
                .checked_add(lut_bytes)
                .ok_or_else(|| "Class 5 descriptor size overflow".to_string())?;
            let next = check_desc(pos, total_need)?;
            let q = f32_le(b, blk_off + pos + 12);
            let off = f32_le(b, blk_off + pos + 16);
            let lut_slice = &b[blk_off + pos + 20..blk_off + next];
            let lut_bits = lut_dwords
                .checked_mul(32)
                .ok_or_else(|| "Class 5 lut bit count overflow".to_string())?;
            let n_lut = lut_bits / val_bits;
            let mut lut = Vec::with_capacity(n_lut);
            for i in 0..n_lut {
                let u = read_bits_le(lut_slice, i * val_bits, val_bits);
                lut.push(off + (u as f32) * q);
            }
            c5_bits_sum = c5_bits_sum
                .checked_add(idx_bits)
                .ok_or_else(|| "Class 5 bit sum overflow".to_string())?;
            c5.push((idx_bits, lut));
            pos = next;
        }

        // Class 10: 64-frame superblock + 8-lane SIMD 2nd-order delta channels
        let mut class10_verified = 0usize;
        for &sl in &idxs[10] {
            check_desc(pos, 4)?;
            let dw = u32_le(b, blk_off + pos) as usize;
            let dw_bytes = dw
                .checked_mul(4)
                .ok_or_else(|| "Class 10 dword count overflow".to_string())?;
            let next = check_desc(pos, dw_bytes)?;
            let raw = &b[blk_off + pos..blk_off + next];
            let (vals, off_ok, anc_ok) = decode_class10_channel(num_frames, raw)?;
            if !off_ok || !anc_ok {
                return Err(format!(
                    "Class 10 verification failed at slot {sl} (off_ok={off_ok}, anc_ok={anc_ok})"
                ));
            }
            class10_verified += 1;
            if sl < num_slots {
                slot_frames[sl] = vals;
            }
            pos = next;
        }

        if pos != desc_end {
            return Err(format!(
                "Channel stream ended at 0x{pos:x}, expected 0x{desc_end:x}"
            ));
        }

        // Unpack per-frame bitstream for Class 4 and Class 5
        if !q4.is_empty() || !c5.is_empty() {
            let total_frame_bits = bits_per_frame
                .checked_add(c5_bits_sum)
                .ok_or_else(|| "Per-frame bit budget overflow".to_string())?;
            let stride_bits = frame_stride
                .checked_mul(8)
                .ok_or_else(|| "Frame stride bit count overflow".to_string())?;
            if total_frame_bits > stride_bits {
                return Err(format!(
                    "Per-frame bits ({total_frame_bits}) exceed frame_stride ({stride_bits} bits)"
                ));
            }
            let frame_base = blk_off + desc_end;
            for fi in 0..num_frames {
                let fslice = &b[frame_base + fi * frame_stride..frame_base + (fi + 1) * frame_stride];
                let mut bp = 0usize;
                for (qi, &(nbits, q, off)) in q4.iter().enumerate() {
                    let u = read_bits_le(fslice, bp, nbits);
                    bp += nbits;
                    let sl = idxs[4][qi];
                    if sl < num_slots {
                        slot_frames[sl][fi] = off + (u as f32) * q;
                    }
                }
                for (ci5, (idx_bits, lut)) in c5.iter().enumerate() {
                    let u = read_bits_le(fslice, bp, *idx_bits) as usize;
                    bp += *idx_bits;
                    let sl = idxs[5][ci5];
                    if sl < num_slots && u < lut.len() {
                        slot_frames[sl][fi] = lut[u];
                    }
                }
            }
        }

        // Class 7: Reconstruct missing quaternion component k from (base+0, base+1, base+2)
        // and insert r at index k of (a, b, c), then normalize.
        for &sl in &idxs[7] {
            let base = sl & !3;
            let comp = sl & 3;
            if base + 3 < num_slots {
                for fi in 0..num_frames {
                    let a = slot_frames[base][fi];
                    let b_v = slot_frames[base + 1][fi];
                    let c = slot_frames[base + 2][fi];
                    let r = (1.0f32 - (a * a + b_v * b_v + c * c)).max(0.0).sqrt();
                    let mut q = match comp {
                        0 => [r, a, b_v, c],
                        1 => [a, r, b_v, c],
                        2 => [a, b_v, r, c],
                        _ => [a, b_v, c, r],
                    };
                    let nrm = (q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3]).sqrt();
                    if nrm > 1e-8 {
                        q[0] /= nrm;
                        q[1] /= nrm;
                        q[2] /= nrm;
                        q[3] /= nrm;
                    }
                    slot_frames[base][fi] = q[0];
                    slot_frames[base + 1][fi] = q[1];
                    slot_frames[base + 2][fi] = q[2];
                    slot_frames[base + 3][fi] = q[3];
                }
            }
        }

        // Class 8: Normalize 4-component explicitly-stored quaternion
        for &sl in &idxs[8] {
            let base = sl & !3;
            if base + 3 < num_slots {
                for fi in 0..num_frames {
                    let x = slot_frames[base][fi];
                    let y = slot_frames[base + 1][fi];
                    let z = slot_frames[base + 2][fi];
                    let w = slot_frames[base + 3][fi];
                    let nrm = (x * x + y * y + z * z + w * w).sqrt();
                    if nrm > 1e-8 {
                        slot_frames[base][fi] = x / nrm;
                        slot_frames[base + 1][fi] = y / nrm;
                        slot_frames[base + 2][fi] = z / nrm;
                        slot_frames[base + 3][fi] = w / nrm;
                    }
                }
            }
        }

        Ok(Self {
            offset: blk_off,
            signature,
            num_frames,
            frame_stride,
            bits_per_frame,
            class_counts,
            trailer_records,
            class10_verified,
            slot_frames,
        })
    }
}

impl CrAnimation {
    pub fn parse(b: &[u8], off: usize, hash: u32) -> Result<Self, String> {
        if off + 0x70 > b.len() {
            return Err("crAnimation header out of bounds".into());
        }
        let flags = u16_le(b, off + 0x20);
        let num_frames = u16_le(b, off + 0x24) as usize;
        let seq_frames = u16_le(b, off + 0x26) as usize;
        let duration = f32_le(b, off + 0x28);
        let signature = u32_le(b, off + 0x2c);
        let name = sys_ptr(b, off + 0x30)
            .and_then(|p| read_cstr(b, p))
            .unwrap_or_else(|| format!("anim_{hash:08x}"));
        let max_block_size = u32_le(b, off + 0x48);

        let blk_arr = sys_ptr(b, off + 0x50).ok_or("Missing crAnimation block array ptr")?;
        let blk_cnt = u16_le(b, off + 0x58) as usize;
        let trk_arr = sys_ptr(b, off + 0x60).ok_or("Missing crAnimation track array ptr")?;
        let trk_cnt = u16_le(b, off + 0x68) as usize;

        let mut tracks = Vec::with_capacity(trk_cnt);
        for ti in 0..trk_cnt {
            let p = trk_arr + ti * 12;
            if p + 12 > b.len() {
                return Err("Track descriptor out of bounds".into());
            }
            let bone_id = u32_le(b, p);
            let track_type = u32_le(b, p + 4);
            let raw_vt = u32_le(b, p + 8);
            tracks.push(AnimTrackDesc {
                bone_id,
                track_type,
                value_type: TrackValueType::from_u32(raw_vt),
                raw_value_type: raw_vt,
            });
        }

        let mut blocks = Vec::with_capacity(blk_cnt);
        for bi in 0..blk_cnt {
            let blk_off =
                sys_ptr(b, blk_arr + bi * 8).ok_or("Invalid crAnimSequence block pointer")?;
            blocks.push(DecodedAnimBlock::parse(b, blk_off, trk_cnt)?);
        }

        // Stitch multi-block frames across the animation (boundary frame 0 of block bi > 0 overlaps last frame of block bi - 1)
        let mut track_frames = Vec::with_capacity(trk_cnt);
        for (ti, trk) in tracks.iter().enumerate() {
            let sl = ti * 4;
            match trk.value_type {
                TrackValueType::Quaternion => {
                    let mut quats = Vec::with_capacity(num_frames);
                    for (bi, blk) in blocks.iter().enumerate() {
                        let start_f = if bi == 0 { 0 } else { 1 };
                        for fi in start_f..blk.num_frames {
                            let x = blk.slot_frames.get(sl).map_or(0.0, |v| v[fi]);
                            let y = blk.slot_frames.get(sl + 1).map_or(0.0, |v| v[fi]);
                            let z = blk.slot_frames.get(sl + 2).map_or(0.0, |v| v[fi]);
                            let w = blk.slot_frames.get(sl + 3).map_or(1.0, |v| v[fi]);
                            quats.push([x, y, z, w]);
                        }
                    }
                    track_frames.push(DecodedTrackFrames::Quaternions(quats));
                }
                TrackValueType::Vector3 => {
                    let mut vecs = Vec::with_capacity(num_frames);
                    for (bi, blk) in blocks.iter().enumerate() {
                        let start_f = if bi == 0 { 0 } else { 1 };
                        for fi in start_f..blk.num_frames {
                            let x = blk.slot_frames.get(sl).map_or(0.0, |v| v[fi]);
                            let y = blk.slot_frames.get(sl + 1).map_or(0.0, |v| v[fi]);
                            let z = blk.slot_frames.get(sl + 2).map_or(0.0, |v| v[fi]);
                            vecs.push([x, y, z]);
                        }
                    }
                    track_frames.push(DecodedTrackFrames::Vectors(vecs));
                }
                _ => {
                    let mut flts = Vec::with_capacity(num_frames);
                    for (bi, blk) in blocks.iter().enumerate() {
                        let start_f = if bi == 0 { 0 } else { 1 };
                        for fi in start_f..blk.num_frames {
                            let x = blk.slot_frames.get(sl).map_or(0.0, |v| v[fi]);
                            flts.push(x);
                        }
                    }
                    track_frames.push(DecodedTrackFrames::Floats(flts));
                }
            }
        }

        Ok(Self {
            offset: off,
            hash,
            name,
            flags,
            num_frames,
            seq_frames,
            duration,
            signature,
            max_block_size,
            tracks,
            blocks,
            track_frames,
        })
    }
}

impl CrClip {
    pub fn parse(b: &[u8], off: usize, hash: u32) -> Result<Self, String> {
        if off + 0x80 > b.len() {
            return Err("crClip header out of bounds".into());
        }
        let name = sys_ptr(b, off + 0x28)
            .and_then(|p| read_cstr(b, p))
            .unwrap_or_else(|| format!("clip_{hash:08x}"));
        let duration = f32_le(b, off + 0x78);

        let mut bindings = Vec::new();
        if let Some(holder) = sys_ptr(b, off + 0x68) {
            if holder + 16 <= b.len() {
                if let Some(arr_ptr) = sys_ptr(b, holder) {
                    let cnt = u16_le(b, holder + 8) as usize;
                    for i in 0..cnt {
                        let ep = arr_ptr + i * 0x38;
                        if ep + 0x38 <= b.len() {
                            if let Some(anim_offset) = sys_ptr(b, ep) {
                                bindings.push(ClipAnimBinding {
                                    anim_offset,
                                    anim_hash: u32_le(b, ep + 0x08),
                                    start_time: f32_le(b, ep + 0x28),
                                    end_time: f32_le(b, ep + 0x2c),
                                    rate: f32_le(b, ep + 0x30),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            offset: off,
            hash,
            name,
            duration,
            bindings,
        })
    }
}

impl CrClipDictionary {
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        if b.len() < 0x80 {
            return Err("Buffer too small for crClipDictionary".into());
        }
        let name = sys_ptr(b, 0x38)
            .and_then(|p| read_cstr(b, p))
            .unwrap_or_else(|| "unnamed_clip_dict".into());

        let clip_buckets = sys_ptr(b, 0x48).ok_or("Missing clip map buckets pointer")?;
        let clip_bcnt = u16_le(b, 0x50) as usize;
        let clip_entries = walk_at_map(b, clip_buckets, clip_bcnt);

        let mut clips = Vec::with_capacity(clip_entries.len());
        for (ch, cp) in clip_entries {
            clips.push(CrClip::parse(b, cp, ch)?);
        }

        let mut anim_dict_name = String::new();
        let mut animations = Vec::new();
        if let Some(p70) = sys_ptr(b, 0x70) {
            let c78 = u16_le(b, 0x78) as usize;
            for ai in 0..c78 {
                let Some(entry_off) = ai.checked_mul(16).and_then(|d| p70.checked_add(d)) else {
                    break;
                };
                if let Some(ad) = sys_ptr(b, entry_off) {
                    if anim_dict_name.is_empty() {
                        anim_dict_name = ad
                            .checked_add(0x38)
                            .and_then(|o| sys_ptr(b, o))
                            .and_then(|p| read_cstr(b, p))
                            .unwrap_or_default();
                    }
                    if ad.checked_add(0x52).is_some_and(|e| e <= b.len()) {
                        if let Some(abuckets) = sys_ptr(b, ad + 0x48) {
                            let abcnt = u16_le(b, ad + 0x50) as usize;
                            for (ah, ap) in walk_at_map(b, abuckets, abcnt) {
                                animations.push(CrAnimation::parse(b, ap, ah)?);
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            name,
            anim_dict_name,
            clips,
            animations,
        })
    }

    /// Export the first animation (or specified index) to a valid binary glTF 2.0 (`.glb`) blob.
    pub fn export_animation_glb(&self, anim_idx: usize) -> Result<Vec<u8>, String> {
        let anim = self
            .animations
            .get(anim_idx)
            .ok_or("Animation index out of range")?;
        export_cr_animation_to_glb(anim)
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[inline]
fn sanitize_quat(q: [f32; 4]) -> [f32; 4] {
    if !q.iter().all(|c| c.is_finite()) {
        return [0.0, 0.0, 0.0, 1.0];
    }
    let nrm = (q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3]).sqrt();
    if !nrm.is_finite() || nrm <= 1e-8 {
        return [0.0, 0.0, 0.0, 1.0];
    }
    [q[0] / nrm, q[1] / nrm, q[2] / nrm, q[3] / nrm]
}

#[inline]
fn sanitize_vec3(v: [f32; 3]) -> [f32; 3] {
    [
        if v[0].is_finite() { v[0] } else { 0.0 },
        if v[1].is_finite() { v[1] } else { 0.0 },
        if v[2].is_finite() { v[2] } else { 0.0 },
    ]
}

/// Standard glTF 2.0 binary (`.glb`) exporter for a decoded `CrAnimation`.
/// Exports all bone rotation (`ROTATION`, `VEC4`) and bone translation (`TRANSLATION`, `VEC3`)
/// tracks on named skeleton nodes.
pub fn export_cr_animation_to_glb(anim: &CrAnimation) -> Result<Vec<u8>, String> {
    let nf = anim.num_frames;
    if nf == 0 {
        return Err("Animation has 0 frames".into());
    }
    if anim.track_frames.len() != anim.tracks.len() {
        return Err(format!(
            "Track frame count mismatch: {} tracks vs {} decoded frame lists",
            anim.tracks.len(),
            anim.track_frames.len()
        ));
    }
    let dt = if nf > 1 && anim.duration.is_finite() && anim.duration > 0.0 {
        let step = anim.duration / ((nf - 1) as f32);
        if step.is_finite() && step > 0.0 {
            step
        } else {
            1.0 / 30.0
        }
    } else {
        1.0 / 30.0
    };

    // Collect unique bone IDs that have rotation or translation tracks
    let mut bone_ids: Vec<u32> = Vec::new();
    for trk in &anim.tracks {
        if matches!(
            trk.value_type,
            TrackValueType::Quaternion | TrackValueType::Vector3
        ) && !bone_ids.contains(&trk.bone_id)
        {
            bone_ids.push(trk.bone_id);
        }
    }
    if bone_ids.is_empty() {
        bone_ids.push(0);
    }

    // Build binary buffer:
    // Accessor 0: time stamps (nf * f32)
    let mut bin_buf: Vec<u8> = Vec::new();
    let mut max_time = 0.0f32;
    for fi in 0..nf {
        let t = (fi as f32) * dt;
        bin_buf.extend_from_slice(&t.to_le_bytes());
        max_time = t;
    }

    let mut buffer_views_json = Vec::new();
    let mut accessors_json = Vec::new();
    let mut samplers_json = Vec::new();
    let mut channels_json = Vec::new();

    // BufferView 0 & Accessor 0 = time input (exact f32 value so JSON max matches BIN)
    buffer_views_json.push(format!(
        "{{\"buffer\":0,\"byteOffset\":0,\"byteLength\":{}}}",
        nf * 4
    ));
    accessors_json.push(format!(
        "{{\"bufferView\":0,\"componentType\":5126,\"count\":{nf},\"type\":\"SCALAR\",\"min\":[0.0],\"max\":[{max_time}]}}"
    ));

    // Export primary bone rotation/translation tracks first, then any remaining non-duplicate tracks
    let mut order: Vec<usize> = (0..anim.tracks.len()).collect();
    order.sort_by_key(|&ti| match anim.tracks[ti].track_type {
        0x98e1750c | 0xf791a95f => 0u8, // bonerotation / bonetranslation
        _ => 1u8,
    });
    let mut seen_targets: HashSet<(usize, &'static str)> = HashSet::new();

    for ti in order {
        let trk = &anim.tracks[ti];
        let Some(node_idx) = bone_ids.iter().position(|&id| id == trk.bone_id) else {
            continue;
        };
        // Only export primary bone rotation / translation / mover tracks to glTF node TRS
        let target_path = match (&anim.track_frames[ti], trk.value_type) {
            (DecodedTrackFrames::Quaternions(_), TrackValueType::Quaternion) => "rotation",
            (DecodedTrackFrames::Vectors(_), TrackValueType::Vector3) => "translation",
            _ => continue,
        };
        if !seen_targets.insert((node_idx, target_path)) {
            continue;
        }
        let byte_offset = bin_buf.len();
        match &anim.track_frames[ti] {
            DecodedTrackFrames::Quaternions(quats) => {
                if quats.len() != nf {
                    return Err(format!(
                        "Track {ti} frame count {} != animation num_frames {nf}",
                        quats.len()
                    ));
                }
                for &q in quats {
                    for c in sanitize_quat(q) {
                        bin_buf.extend_from_slice(&c.to_le_bytes());
                    }
                }
                let byte_len = quats.len() * 16;
                let bv_idx = buffer_views_json.len();
                let acc_idx = accessors_json.len();
                let samp_idx = samplers_json.len();
                buffer_views_json.push(format!(
                    "{{\"buffer\":0,\"byteOffset\":{byte_offset},\"byteLength\":{byte_len}}}"
                ));
                accessors_json.push(format!(
                    "{{\"bufferView\":{bv_idx},\"componentType\":5126,\"count\":{},\"type\":\"VEC4\"}}",
                    quats.len()
                ));
                samplers_json.push(format!(
                    "{{\"input\":0,\"interpolation\":\"LINEAR\",\"output\":{acc_idx}}}"
                ));
                channels_json.push(format!(
                    "{{\"sampler\":{samp_idx},\"target\":{{\"node\":{node_idx},\"path\":\"{target_path}\"}}}}"
                ));
            }
            DecodedTrackFrames::Vectors(vecs) => {
                if vecs.len() != nf {
                    return Err(format!(
                        "Track {ti} frame count {} != animation num_frames {nf}",
                        vecs.len()
                    ));
                }
                for &v in vecs {
                    for c in sanitize_vec3(v) {
                        bin_buf.extend_from_slice(&c.to_le_bytes());
                    }
                }
                let byte_len = vecs.len() * 12;
                let bv_idx = buffer_views_json.len();
                let acc_idx = accessors_json.len();
                let samp_idx = samplers_json.len();
                buffer_views_json.push(format!(
                    "{{\"buffer\":0,\"byteOffset\":{byte_offset},\"byteLength\":{byte_len}}}"
                ));
                accessors_json.push(format!(
                    "{{\"bufferView\":{bv_idx},\"componentType\":5126,\"count\":{},\"type\":\"VEC3\"}}",
                    vecs.len()
                ));
                samplers_json.push(format!(
                    "{{\"input\":0,\"interpolation\":\"LINEAR\",\"output\":{acc_idx}}}"
                ));
                channels_json.push(format!(
                    "{{\"sampler\":{samp_idx},\"target\":{{\"node\":{node_idx},\"path\":\"{target_path}\"}}}}"
                ));
            }
            DecodedTrackFrames::Floats(_) => {}
        }
    }

    while (bin_buf.len() & 3) != 0 {
        bin_buf.push(0);
    }

    // Build nodes array (node 0 is root, or all nodes listed in scene)
    let mut nodes_json = Vec::with_capacity(bone_ids.len());
    let mut root_nodes = Vec::with_capacity(bone_ids.len());
    for (ni, &bid) in bone_ids.iter().enumerate() {
        let bname = resolve_known_hash(bid)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("bone_{bid:08x}"));
        nodes_json.push(format!("{{\"name\":\"{}\"}}", json_escape(&bname)));
        root_nodes.push(ni.to_string());
    }

    let clean_name = json_escape(&anim.name);
    let anims_field = if channels_json.is_empty() {
        String::new()
    } else {
        format!(
            ",\"animations\":[{{\"name\":\"{}\",\"samplers\":[{}],\"channels\":[{}]}}]",
            clean_name,
            samplers_json.join(","),
            channels_json.join(",")
        )
    };
    let gltf_json = format!(
        "{{\"asset\":{{\"version\":\"2.0\",\"generator\":\"rage9-re\"}},\"scene\":0,\"scenes\":[{{\"nodes\":[{}]}}],\"nodes\":[{}],\"buffers\":[{{\"byteLength\":{}}}],\"bufferViews\":[{}],\"accessors\":[{}]{}}}",
        root_nodes.join(","),
        nodes_json.join(","),
        bin_buf.len(),
        buffer_views_json.join(","),
        accessors_json.join(","),
        anims_field
    );

    let mut json_bytes = gltf_json.into_bytes();
    while (json_bytes.len() & 3) != 0 {
        json_bytes.push(b' ');
    }

    let total_len = 12 + 8 + json_bytes.len() + 8 + bin_buf.len();
    let mut glb = Vec::with_capacity(total_len);
    glb.extend_from_slice(b"glTF");
    glb.extend_from_slice(&2u32.to_le_bytes());
    glb.extend_from_slice(&(total_len as u32).to_le_bytes());
    glb.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    glb.extend_from_slice(&0x4E4F534Au32.to_le_bytes()); // "JSON"
    glb.extend_from_slice(&json_bytes);
    glb.extend_from_slice(&(bin_buf.len() as u32).to_le_bytes());
    glb.extend_from_slice(&0x004E4942u32.to_le_bytes()); // "BIN\0"
    glb.extend_from_slice(&bin_buf);

    Ok(glb)
}
