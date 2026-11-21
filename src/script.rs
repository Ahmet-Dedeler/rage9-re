// SPDX-License-Identifier: MIT OR Apache-2.0
//! RAGE9 `script.rpf` decoders:
//! 1. `PSIN` (PSO v122) container & schema parser (`PSIN -> LSCH -> LENM -> LSNS -> LGID -> LRSC -> CHKS`)
//! 2. Compiled Binary-XML Script-Data DOM tree decoder (`0xde396fe2`) + XML/JSON reconstructor
//! 3. Serialised Object Graph (`0x71717171` tagged-pointer forest) parser & disassembler

use crate::rpf9::resolve_known_hash;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoMemberSchema {
    pub name_hash: u32,
    pub offset: u32,
    pub field_type: u8,
    pub sub_type: u8,
    pub reference: u16,
    pub extra: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoStructSchema {
    pub name_hash: u32,
    pub signature: u32,
    pub flags: u32,
    pub size: u32,
    pub members: Vec<PsoMemberSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoEnumSchema {
    pub name_hash: u32,
    pub signature: u32,
    pub values: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoInstanceBlock {
    pub index_1based: usize,
    pub type_hash: u32,
    pub byte_size: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsnsSection {
    pub count: u32,
    pub flags: u32,
    pub tail_len: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsinDocument {
    pub root_block_index: u32,
    pub prd0_version: u32,
    pub structs: Vec<PsoStructSchema>,
    pub enums: Vec<PsoEnumSchema>,
    pub blocks: Vec<PsoInstanceBlock>,
    pub lsns: LsnsSection,
    pub lgid: Vec<u8>,
    pub chks_file_size: u32,
    pub chks_checksum: u32,
    pub chks_tag: [u8; 4],
}

#[inline]
fn align16(x: usize) -> usize {
    (x + 15) & !15
}

#[inline]
fn u16_le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

#[inline]
fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[inline]
fn u32_be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[inline]
fn u64_le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[inline]
fn f32_le(b: &[u8], o: usize) -> f32 {
    f32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

impl PsinDocument {
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 16 || &buf[..4] != b"PSIN" {
            return Err("Buffer does not start with PSIN magic".into());
        }
        let mut secs: HashMap<[u8; 4], &[u8]> = HashMap::new();
        let mut pos = 0usize;
        while pos + 8 <= buf.len() {
            let tag: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
            if !tag.iter().all(|&c| (32..127).contains(&c)) {
                return Err(format!("Invalid section tag at 0x{pos:x}"));
            }
            let sz = u32_be(buf, pos + 4) as usize;
            if sz < 8 || pos + sz > buf.len() {
                return Err(format!("Section {tag:?} length {sz} out of bounds at 0x{pos:x}"));
            }
            secs.insert(tag, &buf[pos + 8..pos + sz]);
            pos += sz;
        }
        if pos != buf.len() {
            return Err(format!("PSIN section walk ended at {pos}, file len {}", buf.len()));
        }

        let lrsc = secs.get(b"LRSC").ok_or("Missing LRSC section")?;
        if lrsc.len() != 80 || &lrsc[..4] != b"0DRP" {
            return Err("Invalid LRSC 0DRP header".into());
        }
        let prd0_version = u32_le(lrsc, 4);
        let root_block_index = u32_le(lrsc, 0x10);
        let n_structs = u16_le(lrsc, 0x38) as usize;
        let n_enums = u16_le(lrsc, 0x3a) as usize;
        let n_blocks = u16_le(lrsc, 0x3c) as usize;

        let lsch = secs.get(b"LSCH").ok_or("Missing LSCH section")?;
        if lsch.len() < n_structs * 32 {
            return Err("LSCH section too short for struct headers".into());
        }
        let mut raw_structs = Vec::with_capacity(n_structs);
        let mut spos = 0usize;
        let mut total_members = 0usize;
        for _ in 0..n_structs {
            let name_hash = u32_le(lsch, spos);
            let signature = u32_le(lsch, spos + 4);
            let flags = u32_le(lsch, spos + 8);
            let size = u32_le(lsch, spos + 24);
            let nmemb = u16_le(lsch, spos + 30) as usize;
            total_members += nmemb;
            raw_structs.push((name_hash, signature, flags, size, nmemb));
            spos += 32;
        }
        if spos + total_members * 16 != lsch.len() {
            return Err(format!(
                "LSCH length mismatch: expected {}, got {}",
                spos + total_members * 16,
                lsch.len()
            ));
        }
        let mut structs = Vec::with_capacity(n_structs);
        for (name_hash, signature, flags, size, nmemb) in raw_structs {
            let mut members = Vec::with_capacity(nmemb);
            for _ in 0..nmemb {
                members.push(PsoMemberSchema {
                    name_hash: u32_le(lsch, spos),
                    offset: u32_le(lsch, spos + 4),
                    field_type: lsch[spos + 8],
                    sub_type: lsch[spos + 9],
                    reference: u16_le(lsch, spos + 10),
                    extra: u32_le(lsch, spos + 12),
                });
                spos += 16;
            }
            structs.push(PsoStructSchema {
                name_hash,
                signature,
                flags,
                size,
                members,
            });
        }

        let lenm = secs.get(b"LENM").ok_or("Missing LENM section")?;
        if lenm.len() < n_enums * 24 {
            return Err("LENM section too short".into());
        }
        let mut raw_enums = Vec::with_capacity(n_enums);
        let mut epos = 0usize;
        for _ in 0..n_enums {
            let name_hash = u32_le(lenm, epos);
            let signature = u32_le(lenm, epos + 4);
            let count = u32_le(lenm, epos + 16) as usize;
            raw_enums.push((name_hash, signature, count));
            epos += 24;
        }
        let mut enums = Vec::with_capacity(n_enums);
        for (name_hash, signature, count) in raw_enums {
            if epos + count * 16 > lenm.len() {
                return Err("LENM enum values overflow".into());
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push((u64_le(lenm, epos), u64_le(lenm, epos + 8)));
                epos += 16;
            }
            enums.push(PsoEnumSchema {
                name_hash,
                signature,
                values,
            });
        }
        if epos != lenm.len() {
            return Err("LENM trailing bytes".into());
        }

        let psin = secs.get(b"PSIN").ok_or("Missing PSIN section")?;
        if psin.len() < n_blocks * 16 {
            return Err("PSIN block table overflow".into());
        }
        let mut block_headers = Vec::with_capacity(n_blocks);
        for bi in 0..n_blocks {
            let btype = u32_le(psin, bi * 16);
            let bsize = u32_le(psin, bi * 16 + 4);
            block_headers.push((btype, bsize));
        }
        let mut cur_file_off = align16(8 + n_blocks * 16);
        let mut blocks = Vec::with_capacity(n_blocks);
        for (idx0, (btype, bsize)) in block_headers.into_iter().enumerate() {
            let rel = cur_file_off - 8;
            let bsz = bsize as usize;
            if rel + bsz > psin.len() {
                return Err(format!("PSIN block {} payload overflow", idx0 + 1));
            }
            blocks.push(PsoInstanceBlock {
                index_1based: idx0 + 1,
                type_hash: btype,
                byte_size: bsize,
                data: psin[rel..rel + bsz].to_vec(),
            });
            cur_file_off = align16(cur_file_off + bsz);
        }
        if cur_file_off - 8 != psin.len() {
            return Err(format!(
                "PSIN end mismatch: {} vs {}",
                cur_file_off - 8,
                psin.len()
            ));
        }

        let lsns_raw = secs.get(b"LSNS").ok_or("Missing LSNS section")?;
        if lsns_raw.len() < 12 {
            return Err("LSNS section shorter than 12-byte header".into());
        }
        let lsns_count = u32_le(lsns_raw, 0);
        let lsns_flags = u32_le(lsns_raw, 4);
        let lsns_tail_len = u32_le(lsns_raw, 8);
        if lsns_tail_len as usize != lsns_raw.len() - 12 {
            return Err("LSNS tail_len mismatch".into());
        }
        let lsns = LsnsSection {
            count: lsns_count,
            flags: lsns_flags,
            tail_len: lsns_tail_len,
            payload: lsns_raw[12..].to_vec(),
        };

        let lgid = secs.get(b"LGID").copied().unwrap_or(&[]).to_vec();

        let chks = secs.get(b"CHKS").ok_or("Missing CHKS section")?;
        if chks.len() != 12 {
            return Err("CHKS section must be 12 bytes".into());
        }
        let chks_file_size = u32_be(chks, 0);
        let chks_checksum = u32_be(chks, 4);
        let chks_tag: [u8; 4] = chks[8..12].try_into().unwrap();
        if chks_file_size as usize != buf.len() {
            return Err(format!(
                "CHKS file size {} != buffer length {}",
                chks_file_size,
                buf.len()
            ));
        }

        Ok(Self {
            root_block_index,
            prd0_version,
            structs,
            enums,
            blocks,
            lsns,
            lgid,
            chks_file_size,
            chks_checksum,
            chks_tag,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScriptAttrValue {
    StringIndex(u32),
    Vector([f32; 3]),
    Float(f32),
    Int(i32),
    Bool(bool),
    Hash64(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScriptAttribute {
    pub name_hash: u32,
    pub value_hash: u32,
    pub raw_val: u32,
    pub attr_type: u8,
    pub is_valid: bool,
    pub value: ScriptAttrValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptDataNode {
    pub name_hash: u32,
    pub parent_index: u16,
    pub child_index: u16,
    pub sibling_index: u16,
    pub prev_sibling_index: u16,
    pub attribute_start: u16,
    pub attribute_count: u8,
    pub is_valid: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScriptDataTree {
    pub attributes: Vec<ScriptAttribute>,
    pub vectors: Vec<[f32; 3]>,
    pub u64_table: Vec<u64>,
    pub nodes: Vec<ScriptDataNode>,
}

impl ScriptDataTree {
    pub const ROOT_STRUCT_HASH: u32 = 0xde396fe2;

    pub fn from_psin(doc: &PsinDocument) -> Result<Self, String> {
        let root_idx = doc.root_block_index as usize;
        if root_idx == 0 || root_idx > doc.blocks.len() {
            return Err("Invalid root_block_index".into());
        }
        let root_blk = &doc.blocks[root_idx - 1];
        if root_blk.type_hash != Self::ROOT_STRUCT_HASH || root_blk.data.len() != 0x50 {
            return Err(format!(
                "Unexpected root block type 0x{:08x} or size {}",
                root_blk.type_hash,
                root_blk.data.len()
            ));
        }

        let decode_arr_ref = |off: usize| -> (usize, usize, usize) {
            let cnt = u32_le(&root_blk.data, off) as usize;
            let r = u64_le(&root_blk.data, off + 8);
            let bidx = (r & 0xfff) as usize;
            let boff = (r >> 20) as usize;
            (cnt, bidx, boff)
        };

        let (n_attrs, b_attrs, o_attrs) = decode_arr_ref(0x00);
        let (_n_strs, _b_strs, _o_strs) = decode_arr_ref(0x10);
        let (n_vecs, b_vecs, o_vecs) = decode_arr_ref(0x20);
        let (n_u64s, b_u64s, o_u64s) = decode_arr_ref(0x30);
        let (n_nodes, b_nodes, o_nodes) = decode_arr_ref(0x40);

        let mut vectors = Vec::with_capacity(n_vecs);
        if n_vecs > 0 {
            let blk = &doc.blocks.get(b_vecs.wrapping_sub(1)).ok_or("Invalid vec block")?.data;
            if o_vecs + n_vecs * 12 > blk.len() {
                return Err("Vector array out of bounds".into());
            }
            for i in 0..n_vecs {
                let p = o_vecs + i * 12;
                vectors.push([f32_le(blk, p), f32_le(blk, p + 4), f32_le(blk, p + 8)]);
            }
        }

        let mut u64_table = Vec::with_capacity(n_u64s);
        if n_u64s > 0 {
            let blk = &doc.blocks.get(b_u64s.wrapping_sub(1)).ok_or("Invalid u64 block")?.data;
            if o_u64s + n_u64s * 8 > blk.len() {
                return Err("u64 array out of bounds".into());
            }
            for i in 0..n_u64s {
                u64_table.push(u64_le(blk, o_u64s + i * 8));
            }
        }

        let mut attributes = Vec::with_capacity(n_attrs);
        if n_attrs > 0 {
            let blk = &doc.blocks.get(b_attrs.wrapping_sub(1)).ok_or("Invalid attr block")?.data;
            if o_attrs + n_attrs * 16 > blk.len() {
                return Err("Attribute array out of bounds".into());
            }
            for i in 0..n_attrs {
                let p = o_attrs + i * 16;
                let name_hash = u32_le(blk, p);
                let value_hash = u32_le(blk, p + 4);
                let raw_val = u32_le(blk, p + 8);
                let attr_type = blk[p + 12];
                let is_valid = blk[p + 13] != 0;
                let value = match attr_type {
                    0 => ScriptAttrValue::StringIndex(raw_val),
                    1 => {
                        let vi = raw_val as usize;
                        if vi >= vectors.len() {
                            return Err(format!("Vector index {vi} >= {}", vectors.len()));
                        }
                        ScriptAttrValue::Vector(vectors[vi])
                    }
                    2 => ScriptAttrValue::Float(f32::from_bits(raw_val)),
                    3 => ScriptAttrValue::Int(raw_val as i32),
                    4 => ScriptAttrValue::Bool(raw_val != 0),
                    5 => {
                        let hi = raw_val as usize;
                        if hi >= u64_table.len() {
                            return Err(format!("u64 index {hi} >= {}", u64_table.len()));
                        }
                        ScriptAttrValue::Hash64(u64_table[hi])
                    }
                    other => return Err(format!("Unknown attribute enum type {other}")),
                };
                attributes.push(ScriptAttribute {
                    name_hash,
                    value_hash,
                    raw_val,
                    attr_type,
                    is_valid,
                    value,
                });
            }
        }

        let mut nodes = Vec::with_capacity(n_nodes);
        if n_nodes > 0 {
            let blk = &doc.blocks.get(b_nodes.wrapping_sub(1)).ok_or("Invalid node block")?.data;
            if o_nodes + n_nodes * 16 > blk.len() {
                return Err("Node array out of bounds".into());
            }
            for i in 0..n_nodes {
                let p = o_nodes + i * 16;
                let node = ScriptDataNode {
                    name_hash: u32_le(blk, p),
                    parent_index: u16_le(blk, p + 4),
                    child_index: u16_le(blk, p + 6),
                    sibling_index: u16_le(blk, p + 8),
                    prev_sibling_index: u16_le(blk, p + 10),
                    attribute_start: u16_le(blk, p + 12),
                    attribute_count: blk[p + 14],
                    is_valid: blk[p + 15] != 0,
                };
                let check_idx = |idx: u16| idx == 0xffff || (idx as usize) < n_nodes;
                if !check_idx(node.parent_index)
                    || !check_idx(node.child_index)
                    || !check_idx(node.sibling_index)
                    || !check_idx(node.prev_sibling_index)
                {
                    return Err(format!("Node {i} link index out of range"));
                }
                if node.attribute_count > 0
                    && (node.attribute_start as usize) + (node.attribute_count as usize) > n_attrs
                {
                    return Err(format!("Node {i} attribute slice out of range"));
                }
                nodes.push(node);
            }
        }

        Ok(Self {
            attributes,
            vectors,
            u64_table,
            nodes,
        })
    }

    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        if self.nodes.is_empty() {
            return out;
        }
        self.write_node_xml(0, 0, &mut out);
        out
    }

    fn write_node_xml(&self, idx: usize, depth: usize, out: &mut String) {
        if idx >= self.nodes.len() {
            return;
        }
        let node = &self.nodes[idx];
        let indent = "  ".repeat(depth);
        let tag_name = resolve_known_hash(node.name_hash)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("node_{:08x}", node.name_hash));
        out.push_str(&format!("{indent}<{tag_name}"));
        if node.attribute_count > 0 {
            let a_start = node.attribute_start as usize;
            let a_end = a_start + (node.attribute_count as usize);
            for attr in &self.attributes[a_start..a_end] {
                let aname = resolve_known_hash(attr.name_hash)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("attr_{:08x}", attr.name_hash));
                let aval = match attr.value {
                    ScriptAttrValue::StringIndex(i) => format!("str#{i}"),
                    ScriptAttrValue::Vector([x, y, z]) => format!("{x:.4},{y:.4},{z:.4}"),
                    ScriptAttrValue::Float(v) => format!("{v:.6}"),
                    ScriptAttrValue::Int(v) => format!("{v}"),
                    ScriptAttrValue::Bool(v) => format!("{v}"),
                    ScriptAttrValue::Hash64(h) => format!("0x{h:016x}"),
                };
                out.push_str(&format!(" {aname}=\"{aval}\""));
            }
        }
        if node.child_index == 0xffff {
            out.push_str(" />\n");
        } else {
            out.push_str(">\n");
            let mut ch = node.child_index;
            let mut guard = 0usize;
            while ch != 0xffff && (ch as usize) < self.nodes.len() && guard < self.nodes.len() {
                self.write_node_xml(ch as usize, depth + 1, out);
                ch = self.nodes[ch as usize].sibling_index;
                guard += 1;
            }
            out.push_str(&format!("{indent}</{tag_name}>\n"));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectGraphRecord {
    pub index: usize,
    pub offset: usize,
    pub size: usize,
    pub root_id: u32,
    pub type_hash: u64,
    pub array_info: Option<(u32, u32)>, // (count, stride) when type_hash == 0x14
    pub pointers: Vec<(usize, usize)>,  // (field_rel_offset, target_record_index)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectGraph {
    pub records: Vec<ObjectGraphRecord>,
    pub root_indices: Vec<usize>,
    pub total_pointers: usize,
}

impl ObjectGraph {
    pub const PTR_TAG: u32 = 0x71717171;
    pub const ARRAY_TYPE: u64 = 0x14;

    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 0x30 {
            return Err("ObjectGraph buffer too short".into());
        }
        let rec_count = u32_le(buf, 0x14) as usize;
        if rec_count == 0 || 0x28 + rec_count * 8 > buf.len() {
            return Err("Invalid ObjectGraph record count".into());
        }
        let mut offsets = Vec::with_capacity(rec_count);
        let mut off_to_idx = HashMap::with_capacity(rec_count);
        for i in 0..rec_count {
            let off = u64_le(buf, 0x28 + i * 8) as usize;
            if i == 0 && off != align16(0x28 + rec_count * 8) {
                return Err(format!(
                    "First record offset 0x{off:x} != aligned table end 0x{:x}",
                    align16(0x28 + rec_count * 8)
                ));
            }
            if (off & 15) != 0 || off >= buf.len() {
                return Err(format!("Unaligned or OOB record offset 0x{off:x}"));
            }
            if i > 0 && off <= offsets[i - 1] {
                return Err("Non-monotonic record offsets".into());
            }
            off_to_idx.insert(off, i);
            offsets.push(off);
        }

        let mut records = Vec::with_capacity(rec_count);
        let mut targeted = HashSet::with_capacity(rec_count);
        let mut total_pointers = 0usize;

        for i in 0..rec_count {
            let off = offsets[i];
            let end = if i + 1 < rec_count {
                offsets[i + 1]
            } else {
                buf.len()
            };
            let sz = end - off;
            if sz < 0x20 || (sz & 15) != 0 {
                return Err(format!("Invalid record size 0x{sz:x} at index {i}"));
            }
            let root_id = u32_le(buf, off);
            let type_hash = u64_le(buf, off + 8);
            let array_info = if type_hash == Self::ARRAY_TYPE {
                let cnt = u32_le(buf, off + 0x10);
                let cnt2 = u32_le(buf, off + 0x14);
                let stride = u32_le(buf, off + 0x18);
                if cnt != cnt2 || align16(0x30 + (cnt as usize) * (stride as usize)) != sz {
                    return Err(format!("Array record {i} size mismatch"));
                }
                Some((cnt, stride))
            } else {
                None
            };

            let mut pointers = Vec::new();
            let mut rel = 0x10usize;
            while rel + 8 <= sz {
                let target_plus8 = u32_le(buf, off + rel) as usize;
                let tag = u32_le(buf, off + rel + 4);
                if tag == Self::PTR_TAG {
                    if target_plus8 < 8 {
                        return Err("Invalid 0x71717171 pointer target < 8".into());
                    }
                    let target_off = target_plus8 - 8;
                    let target_idx = *off_to_idx
                        .get(&target_off)
                        .ok_or_else(|| format!("Pointer to non-record offset 0x{target_off:x}"))?;
                    pointers.push((rel, target_idx));
                    targeted.insert(target_idx);
                    total_pointers += 1;
                }
                rel += 8;
            }

            records.push(ObjectGraphRecord {
                index: i,
                offset: off,
                size: sz,
                root_id,
                type_hash,
                array_info,
                pointers,
            });
        }

        let root_indices: Vec<usize> = (0..rec_count).filter(|i| !targeted.contains(i)).collect();
        Ok(Self {
            records,
            root_indices,
            total_pointers,
        })
    }

    pub fn disassemble_tree(&self, root_idx: usize, max_depth: usize) -> String {
        let mut out = String::new();
        self.fmt_rec(root_idx, 0, max_depth, &mut out);
        out
    }

    fn fmt_rec(&self, idx: usize, depth: usize, max_depth: usize, out: &mut String) {
        if idx >= self.records.len() || depth > max_depth {
            return;
        }
        let rec = &self.records[idx];
        let indent = "  ".repeat(depth);
        if let Some((cnt, stride)) = rec.array_info {
            out.push_str(&format!(
                "{indent}[rec#{idx} @ 0x{:06x}] ARRAY count={cnt} stride={stride} (size=0x{:x})\n",
                rec.offset, rec.size
            ));
        } else {
            out.push_str(&format!(
                "{indent}[rec#{idx} @ 0x{:06x}] type=0x{:08x} id=0x{:08x} (size=0x{:x})\n",
                rec.offset, rec.type_hash, rec.root_id, rec.size
            ));
        }
        for &(rel, target) in &rec.pointers {
            out.push_str(&format!("{indent}  +0x{rel:02x} -> rec#{target}\n"));
            self.fmt_rec(target, depth + 2, max_depth, out);
        }
    }
}
