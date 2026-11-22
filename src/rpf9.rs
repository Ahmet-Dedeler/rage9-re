// rage9-re by Ahmet Dedeler (https://github.com/Ahmet-Dedeler, https://ahmetdedeler.com)
// Source: https://github.com/Ahmet-Dedeler/rage9-re
// SPDX-License-Identifier: MIT OR Apache-2.0
// If you copy, vendor or port this file, keep this header and credit rage9-re in your README.
//! RPF9 container header parser, 16-byte-aligned zlib stream carver,
//! multi-chunk resource stitcher, and JOAAT hash resolver.

use flate2::Decompress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpf9Header {
    pub offset: usize,
    pub toc_end: u32,
    pub field_08: u32,
    pub names_size: u32,
    pub salt: u64,
    pub field_18: u32,
    pub field_1c: u32,
    pub version_level: u16,
    pub field_22: u16,
    pub entry_count: u32,
    pub key_id: u32,
    pub flags: u32,
    pub field_30: u32,
}

impl Rpf9Header {
    pub const MAGIC: &'static [u8; 4] = b"9FPR";

    pub fn parse_at(data: &[u8], offset: usize) -> Option<Self> {
        if offset + 0x40 > data.len() || &data[offset..offset + 4] != Self::MAGIC {
            return None;
        }
        let u32_at = |o: usize| {
            u32::from_le_bytes([
                data[offset + o],
                data[offset + o + 1],
                data[offset + o + 2],
                data[offset + o + 3],
            ])
        };
        let u16_at = |o: usize| u16::from_le_bytes([data[offset + o], data[offset + o + 1]]);
        let salt = u64::from_le_bytes(data[offset + 0x10..offset + 0x18].try_into().ok()?);
        let f18 = u32_at(0x18);
        let f1c = u32_at(0x1c);
        let f30 = u32_at(0x30);
        if f18 != 0x47a00 || f1c != 0x150 || f30 != 0x10 {
            return None;
        }
        Some(Self {
            offset,
            toc_end: u32_at(0x04),
            field_08: u32_at(0x08),
            names_size: u32_at(0x0c),
            salt,
            field_18: f18,
            field_1c: f1c,
            version_level: u16_at(0x20),
            field_22: u16_at(0x22),
            entry_count: u32_at(0x24),
            key_id: u32_at(0x28),
            flags: u32_at(0x2c),
            field_30: f30,
        })
    }

    pub fn scan_all(data: &[u8]) -> Vec<Self> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 0x40 <= data.len() {
            if let Some(rel) = data[pos..].windows(4).position(|w| w == Self::MAGIC) {
                let hit = pos + rel;
                if let Some(hdr) = Self::parse_at(data, hit) {
                    out.push(hdr);
                }
                pos = hit + 4;
            } else {
                break;
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct CarvedZlibStream {
    pub offset: usize,
    pub compressed_len: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Psin,
    ObjectGraph,
    Meta0Drp,
    ClipDictionary,
    Rbf0,
    Xml,
    RageObject,
    Binary,
}

#[derive(Debug, Clone)]
pub struct StitchedEntry {
    pub offset: usize,
    pub stream_count: usize,
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

#[inline]
pub fn is_zlib_header(b: &[u8]) -> bool {
    if b.len() < 2 {
        return false;
    }
    let cmf = b[0] as u16;
    let flg = b[1] as u16;
    if (cmf & 0x0f) != 8 || (cmf >> 4) > 7 {
        return false;
    }
    if (flg & 0x20) != 0 {
        return false;
    }
    ((cmf << 8) | flg) % 31 == 0
}

pub fn try_decompress_zlib(src: &[u8], max_out: usize) -> Option<(Vec<u8>, usize)> {
    if !is_zlib_header(src) {
        return None;
    }
    let mut dec = Decompress::new(true);
    let mut out = Vec::with_capacity(65536);
    let mut tmp = [0u8; 32768];
    let mut in_pos = 0usize;
    loop {
        let before_in = dec.total_in() as usize;
        let before_out = dec.total_out() as usize;
        let status = dec
            .decompress(&src[in_pos..], &mut tmp, flate2::FlushDecompress::None)
            .ok()?;
        let consumed = (dec.total_in() as usize) - before_in;
        let produced = (dec.total_out() as usize) - before_out;
        in_pos += consumed;
        if produced > 0 {
            if out.len() + produced > max_out {
                return None;
            }
            out.extend_from_slice(&tmp[..produced]);
        }
        match status {
            flate2::Status::StreamEnd => {
                if in_pos >= 6 && !out.is_empty() {
                    return Some((out, in_pos));
                }
                return None;
            }
            flate2::Status::Ok => {
                if consumed == 0 && produced == 0 {
                    return None;
                }
            }
            flate2::Status::BufError => return None,
        }
    }
}

pub fn carve_zlib_streams(data: &[u8], start_offset: usize) -> Vec<CarvedZlibStream> {
    let mut streams = Vec::new();
    let mut pos = (start_offset + 15) & !15;
    while pos + 6 <= data.len() {
        if is_zlib_header(&data[pos..]) {
            if let Some((out, consumed)) = try_decompress_zlib(&data[pos..], 64 * 1024 * 1024) {
                streams.push(CarvedZlibStream {
                    offset: pos,
                    compressed_len: consumed,
                    data: out,
                });
                pos = (pos + consumed + 15) & !15;
                continue;
            }
        }
        pos += 16;
    }
    streams
}

pub fn classify_payload(buf: &[u8]) -> EntryKind {
    if buf.len() >= 4 && &buf[..4] == b"PSIN" {
        return EntryKind::Psin;
    }
    if buf.len() >= 0x30
        && buf[..0x14] == [0u8; 0x14]
        && u32::from_le_bytes([buf[0x14], buf[0x15], buf[0x16], buf[0x17]]) > 0
        && buf[0x18..0x28] == [0u8; 0x10]
    {
        let cnt = u32::from_le_bytes([buf[0x14], buf[0x15], buf[0x16], buf[0x17]]) as usize;
        let first_off = u64::from_le_bytes(buf[0x28..0x30].try_into().unwrap()) as usize;
        if first_off == ((0x28 + cnt * 8 + 15) & !15) {
            return EntryKind::ObjectGraph;
        }
    }
    if buf.len() >= 0x20 && &buf[0x10..0x14] == b"0DRP" {
        return EntryKind::Meta0Drp;
    }
    if buf.len() >= 0x80
        && buf[0x10..0x38] == [0u8; 0x28]
        && (buf[0x0b] & 0xf0) == 0x50
        && (buf[0x3b] & 0xf0) == 0x50
        && (buf[0x4b] & 0xf0) == 0x50
    {
        return EntryKind::ClipDictionary;
    }
    if buf.len() >= 4 && &buf[..4] == b"RBF0" {
        return EntryKind::Rbf0;
    }
    if buf.starts_with(b"<?xml") || buf.starts_with(b"<") {
        return EntryKind::Xml;
    }
    if buf.len() >= 16 && (buf[0x0b] & 0xf0) == 0x50 {
        return EntryKind::RageObject;
    }
    EntryKind::Binary
}

pub fn stitch_streams(streams: &[CarvedZlibStream]) -> Vec<StitchedEntry> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i < streams.len() {
        let s0 = &streams[i];
        let mut combined = s0.data.clone();
        let mut count = 1usize;
        let is_resource = s0.data.len() >= 16 && (s0.data[0x0b] & 0xf0) == 0x50;
        let mut j = i + 1;
        while j < streams.len() {
            let prev = &streams[j - 1];
            let cur = &streams[j];
            let prev_end = (prev.offset + prev.compressed_len + 15) & !15;
            if cur.offset != prev_end {
                break;
            }
            if prev.data.len() == 65536 {
                combined.extend_from_slice(&cur.data);
                count += 1;
                j += 1;
            } else if is_resource && (cur.offset & 0xfff) != 0x10 {
                combined.extend_from_slice(&cur.data);
                count += 1;
                j += 1;
            } else {
                break;
            }
        }
        let kind = classify_payload(&combined);
        entries.push(StitchedEntry {
            offset: s0.offset,
            stream_count: count,
            kind,
            data: combined,
        });
        i = j;
    }
    entries
}

/// Standard RAGE Jenkins One-at-a-Time (JOAAT) 32-bit hash.
#[inline]
pub fn joaat(bytes: &[u8], seed: u32) -> u32 {
    let mut h = seed;
    for &b in bytes {
        h = h.wrapping_add(b as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
    }
    h = h.wrapping_add(h << 3);
    h ^= h >> 11;
    h = h.wrapping_add(h << 15);
    h
}

#[inline]
pub fn joaat_str(s: &str) -> u32 {
    joaat(s.as_bytes(), 0)
}

#[inline]
pub fn joaat_lower(s: &str) -> u32 {
    let lower: Vec<u8> = s.bytes().map(|b| b.to_ascii_lowercase()).collect();
    joaat(&lower, 0)
}

/// Resolve known RAGE9 JOAAT hashes (PSO schema fields, script DOM tags, animation tracks, and skeleton bones).
pub fn resolve_known_hash(h: u32) -> Option<&'static str> {
    match h {
        // Script PSIN DOM schema & node/attr names
        0x749dbb9e => Some("attributes"),
        0x2260b8be => Some("dataNodes"),
        0xe6e17f14 => Some("name"),
        0xd89231bd => Some("parentIndex"),
        0x01296aed => Some("childIndex"),
        0x881bf649 => Some("siblingIndex"),
        0xf33047d9 => Some("previousSiblingIndex"),
        0x03341d59 => Some("attributeStart"),
        0x79661755 => Some("attributeCount"),
        0x817ed7a4 => Some("valueHash"),
        0x9303a5e5 => Some("x"),
        0x80950108 => Some("y"),
        0xb6606c9e => Some("z"),
        0xc090afad => Some("root"),
        0x1aecde4d => Some("tag"),
        0x1b60404d => Some("id"),
        0x0c928991 => Some("Position"),
        0x4b621302 => Some("Flags"),
        // Animation track types (joaat lowercase)
        0x98e1750c => Some("bonerotation"),
        0xf791a95f => Some("bonetranslation"),
        0x2deefadd => Some("genericcontrol"),
        0xf5c3a5b6 => Some("generictranslation"),
        0x6ddef121 => Some("cameratranslation"),
        0x60d0644c => Some("firstpersoncameraweight"),
        // Humanoid biped skeleton bone IDs (joaat lowercase)
        0x00000000 => Some("mover"),
        0x6686685c => Some("skel_root"),
        0x8133de19 => Some("skel_pelvis"),
        0x9e0fb7af => Some("skel_spine_root"),
        0x41e5d6a1 => Some("skel_spine0"),
        0xe07293b0 => Some("skel_spine1"),
        0xf242374f => Some("skel_spine2"),
        0x2b3fa955 => Some("skel_spine3"),
        0xfb61fbb5 => Some("skel_l_clavicle"),
        0x3363e579 => Some("skel_l_upperarm"),
        0x052ea8fa => Some("skel_l_forearm"),
        0xa49bbd43 => Some("skel_l_hand"),
        0xb13045dc => Some("skel_r_clavicle"),
        0x0295d8f8 => Some("skel_r_upperarm"),
        0xb409b89d => Some("skel_r_forearm"),
        0xb35aba83 => Some("skel_r_hand"),
        0x3314f242 => Some("skel_l_thigh"),
        0xaf6f89c0 => Some("skel_l_calf"),
        0x3ec3bb37 => Some("skel_l_foot"),
        0x364e7f26 => Some("skel_r_thigh"),
        0xd1bd2d01 => Some("skel_r_calf"),
        0xafce3373 => Some("skel_r_foot"),
        0x3331f5d7 => Some("ph_l_hand"),
        0x81d2d8be => Some("ph_r_hand"),
        0xb14f571a => Some("ik_l_hand"),
        0x04666f78 => Some("ik_r_hand"),
        0x8801c767 => Some("ik_l_foot"),
        0x0e3e181a => Some("ik_r_foot"),
        _ => None,
    }
}
