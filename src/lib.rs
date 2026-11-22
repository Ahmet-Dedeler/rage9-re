// rage9-re by Ahmet Dedeler (https://github.com/Ahmet-Dedeler, https://ahmetdedeler.com)
// Source: https://github.com/Ahmet-Dedeler/rage9-re
// SPDX-License-Identifier: MIT OR Apache-2.0
// If you copy, vendor or port this file, keep this header and credit rage9-re in your README.
//! Clean-room RAGE9 decoder and inspector for `script.rpf` (`PSIN` DOM trees &
//! Serialised Object Graph) and `anim.rpf` (`crClipDictionary`, `crAnimation`,
//! `crAnimSequence` channel codecs, and glTF 2.0 `.glb` exporter).

pub mod anim;
pub mod rpf9;
pub mod script;

#[cfg(test)]
mod tests {
    use super::anim::*;
    use super::rpf9::*;
    use super::script::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_joaat_known_hashes() {
        assert_eq!(joaat_str("attributes"), 0x749dbb9e);
        assert_eq!(joaat_str("dataNodes"), 0x2260b8be);
        assert_eq!(joaat_str("name"), 0xe6e17f14);
        assert_eq!(joaat_str("parentIndex"), 0xd89231bd);
        assert_eq!(joaat_str("childIndex"), 0x01296aed);
        assert_eq!(joaat_str("siblingIndex"), 0x881bf649);
        assert_eq!(joaat_str("previousSiblingIndex"), 0xf33047d9);
        assert_eq!(joaat_str("attributeStart"), 0x03341d59);
        assert_eq!(joaat_str("attributeCount"), 0x79661755);
        assert_eq!(joaat_str("valueHash"), 0x817ed7a4);
        assert_eq!(joaat_str("root"), 0xc090afad);
        assert_eq!(joaat_lower("bonerotation"), 0x98e1750c);
        assert_eq!(joaat_lower("bonetranslation"), 0xf791a95f);
        assert_eq!(joaat_lower("skel_pelvis"), 0x8133de19);
        assert_eq!(resolve_known_hash(0x98e1750c), Some("bonerotation"));
        assert_eq!(resolve_known_hash(0x8133de19), Some("skel_pelvis"));
    }

    #[test]
    fn test_rpf9_header_and_zlib_carver() {
        let mut archive = vec![0u8; 0x100];
        archive[0..4].copy_from_slice(b"9FPR");
        archive[0x04..0x08].copy_from_slice(&0x40u32.to_le_bytes());
        archive[0x18..0x1c].copy_from_slice(&0x47a00u32.to_le_bytes());
        archive[0x1c..0x20].copy_from_slice(&0x150u32.to_le_bytes());
        archive[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
        archive[0x30..0x34].copy_from_slice(&0x10u32.to_le_bytes());

        let hdrs = Rpf9Header::scan_all(&archive);
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs[0].toc_end, 0x40);
        assert_eq!(hdrs[0].entry_count, 1);

        let payload = b"<?xml version=\"1.0\"?><root />";
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let zbytes = enc.finish().unwrap();
        archive[0x40..0x40 + zbytes.len()].copy_from_slice(&zbytes);

        let streams = carve_zlib_streams(&archive, 0x40);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].data, payload);

        let stitched = stitch_streams(&streams);
        assert_eq!(stitched.len(), 1);
        assert_eq!(stitched[0].kind, EntryKind::Xml);
    }

    #[test]
    fn test_synthetic_psin_and_dom_tree() {
        // Build a synthetic valid PSIN document with 1 root struct (0xde396fe2),
        // 2 nodes (root -> child tag), 2 attributes (int + vector), 1 vector, 1 u64.
        let mut psin_sec = Vec::new();
        // 4 blocks in PSIN block table (64 bytes):
        // Block 1: u64 pool (type 0x16, size 8)
        // Block 2: vector pool (type 0xaeb623d8, size 12)
        // Block 3: attribute pool (type 0x85b4c631, size 32 = 2 attrs)
        // Block 4: root struct (type 0xde396fe2, size 0x50)
        // Block 5: node pool (type 0x01393259, size 32 = 2 nodes)
        let block_defs: [(u32, u32); 5] = [
            (0x00000016, 8),
            (0xaeb623d8, 12),
            (0x85b4c631, 32),
            (0xde396fe2, 0x50),
            (0x01393259, 32),
        ];
        for (bt, bsz) in block_defs {
            psin_sec.extend_from_slice(&bt.to_le_bytes());
            psin_sec.extend_from_slice(&bsz.to_le_bytes());
            psin_sec.extend_from_slice(&0xaaaa_aaaa_aaaa_aaaau64.to_le_bytes());
        }
        // 8 bytes header + 5*16 = 88 -> pad +8 bytes to align file offset 96 (0x60)
        psin_sec.extend_from_slice(b"pppppppp");
        // Block 1 (8B + 8B pad):
        psin_sec.extend_from_slice(&0x1122334455667788u64.to_le_bytes());
        psin_sec.extend_from_slice(&[0u8; 8]);
        // Block 2 (12B + 4B pad): vec (1.5, -2.0, 4.25)
        psin_sec.extend_from_slice(&1.5f32.to_le_bytes());
        psin_sec.extend_from_slice(&(-2.0f32).to_le_bytes());
        psin_sec.extend_from_slice(&4.25f32.to_le_bytes());
        psin_sec.extend_from_slice(&[0u8; 4]);
        // Block 3 (32B): 2 attributes
        // Attr 0: id = 42 (type 3 = Int)
        psin_sec.extend_from_slice(&0x1b60404du32.to_le_bytes()); // "id"
        psin_sec.extend_from_slice(&0u32.to_le_bytes());
        psin_sec.extend_from_slice(&42u32.to_le_bytes());
        psin_sec.extend_from_slice(&[3u8, 1u8, 0, 0]);
        // Attr 1: Position = vec#0 (type 1 = Vector)
        psin_sec.extend_from_slice(&0x0c928991u32.to_le_bytes()); // "Position"
        psin_sec.extend_from_slice(&0u32.to_le_bytes());
        psin_sec.extend_from_slice(&0u32.to_le_bytes());
        psin_sec.extend_from_slice(&[1u8, 1u8, 0, 0]);
        // Block 4 (0x50B): root struct with 5 array descriptors {count, cap, ref}
        // arr0 (attrs): count=2, block=3
        psin_sec.extend_from_slice(&2u32.to_le_bytes());
        psin_sec.extend_from_slice(&2u32.to_le_bytes());
        psin_sec.extend_from_slice(&3u64.to_le_bytes());
        // arr1 (strings): count=0
        psin_sec.extend_from_slice(&[0u8; 16]);
        // arr2 (vectors): count=1, block=2
        psin_sec.extend_from_slice(&1u32.to_le_bytes());
        psin_sec.extend_from_slice(&1u32.to_le_bytes());
        psin_sec.extend_from_slice(&2u64.to_le_bytes());
        // arr3 (u64): count=1, block=1
        psin_sec.extend_from_slice(&1u32.to_le_bytes());
        psin_sec.extend_from_slice(&1u32.to_le_bytes());
        psin_sec.extend_from_slice(&1u64.to_le_bytes());
        // arr4 (nodes): count=2, block=5
        psin_sec.extend_from_slice(&2u32.to_le_bytes());
        psin_sec.extend_from_slice(&2u32.to_le_bytes());
        psin_sec.extend_from_slice(&5u64.to_le_bytes());
        // Block 5 (32B): 2 nodes
        // Node 0: "root", parent=FFFF, child=1, sib=FFFF, psib=FFFF, astart=0, acnt=1
        psin_sec.extend_from_slice(&0xc090afadu32.to_le_bytes());
        for w in [0xffffu16, 1, 0xffff, 0xffff, 0] {
            psin_sec.extend_from_slice(&w.to_le_bytes());
        }
        psin_sec.extend_from_slice(&[1u8, 1u8]);
        // Node 1: "tag", parent=0, child=FFFF, sib=FFFF, psib=FFFF, astart=1, acnt=1
        psin_sec.extend_from_slice(&0x1aecde4du32.to_le_bytes());
        for w in [0u16, 0xffff, 0xffff, 0xffff, 1] {
            psin_sec.extend_from_slice(&w.to_le_bytes());
        }
        psin_sec.extend_from_slice(&[1u8, 1u8]);

        // LSCH: 1 struct with 0 members (32B)
        let mut lsch_sec = vec![0u8; 32];
        lsch_sec[0..4].copy_from_slice(&0xde396fe2u32.to_le_bytes());
        lsch_sec[24..28].copy_from_slice(&0x50u32.to_le_bytes());

        // LENM: 0 enums
        let lenm_sec: Vec<u8> = Vec::new();

        // LSNS: 12B header + 16B payload
        let mut lsns_sec = Vec::new();
        lsns_sec.extend_from_slice(&1u32.to_le_bytes());
        lsns_sec.extend_from_slice(&0x0101u32.to_le_bytes());
        lsns_sec.extend_from_slice(&16u32.to_le_bytes());
        lsns_sec.extend_from_slice(&[0x55u8; 16]);

        // LRSC: 80B
        let mut lrsc_sec = vec![0u8; 80];
        lrsc_sec[0..4].copy_from_slice(b"0DRP");
        lrsc_sec[4..8].copy_from_slice(&0x7au32.to_le_bytes());
        lrsc_sec[0x10..0x14].copy_from_slice(&4u32.to_le_bytes()); // root_block_index = 4
        lrsc_sec[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // 1 struct
        lrsc_sec[0x3a..0x3c].copy_from_slice(&0u16.to_le_bytes()); // 0 enums
        lrsc_sec[0x3c..0x3e].copy_from_slice(&5u16.to_le_bytes()); // 5 blocks

        let mut full = Vec::new();
        for (tag, body) in [
            (b"PSIN", &psin_sec),
            (b"LSCH", &lsch_sec),
            (b"LENM", &lenm_sec),
            (b"LSNS", &lsns_sec),
            (b"LGID", &Vec::new()),
            (b"LRSC", &lrsc_sec),
        ] {
            full.extend_from_slice(tag);
            full.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
            full.extend_from_slice(body);
        }
        let total_size = (full.len() + 20) as u32;
        full.extend_from_slice(b"CHKS");
        full.extend_from_slice(&20u32.to_be_bytes());
        full.extend_from_slice(&total_size.to_be_bytes());
        full.extend_from_slice(&0x12345678u32.to_be_bytes());
        full.extend_from_slice(b"zppp");

        let doc = PsinDocument::parse(&full).expect("parse synthetic PSIN");
        assert_eq!(doc.root_block_index, 4);
        assert_eq!(doc.blocks.len(), 5);

        let tree = ScriptDataTree::from_psin(&doc).expect("decode synthetic DOM tree");
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(tree.attributes.len(), 2);
        let xml = tree.to_xml();
        assert!(xml.contains("<root id=\"42\">"));
        assert!(xml.contains("<tag Position=\"1.5000,-2.0000,4.2500\" />"));
    }

    #[test]
    fn test_synthetic_object_graph() {
        // 2 records: rec#0 (root at 0x40, size 0x20, points to rec#1 at 0x60)
        //            rec#1 (array 0x14 at 0x60, count=2, stride=8 -> size=0x40)
        let mut buf = vec![0u8; 0xa0];
        buf[0x14..0x18].copy_from_slice(&2u32.to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&0x40u64.to_le_bytes());
        buf[0x30..0x38].copy_from_slice(&0x60u64.to_le_bytes());

        // rec#0 @ 0x40
        buf[0x40..0x44].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        buf[0x48..0x50].copy_from_slice(&0xc48ab516u64.to_le_bytes());
        buf[0x50..0x54].copy_from_slice(&((0x60 + 8) as u32).to_le_bytes());
        buf[0x54..0x58].copy_from_slice(&ObjectGraph::PTR_TAG.to_le_bytes());

        // rec#1 @ 0x60 (array schema 0x14, count=2, stride=8 -> align16(0x30 + 16) = 0x40)
        buf[0x68..0x70].copy_from_slice(&0x14u64.to_le_bytes());
        buf[0x70..0x74].copy_from_slice(&2u32.to_le_bytes());
        buf[0x74..0x78].copy_from_slice(&2u32.to_le_bytes());
        buf[0x78..0x7c].copy_from_slice(&8u32.to_le_bytes());

        let og = ObjectGraph::parse(&buf).expect("parse synthetic ObjectGraph");
        assert_eq!(og.records.len(), 2);
        assert_eq!(og.root_indices, vec![0]);
        assert_eq!(og.total_pointers, 1);
        let dis = og.disassemble_tree(0, 4);
        assert!(dis.contains("ARRAY count=2 stride=8"));
    }

    #[test]
    fn test_synthetic_class10_2nd_order_delta_and_glb() {
        // Build a synthetic 9-frame Class 10 channel (1 superblock, 1 group of 8 deltas):
        // b4 = 0, b5 = 4 (anchor = 10), b6 = 1
        // Unary run for group 0: bw = 2 (`001` = bit 2 set after 4-bit anchor -> 0x4a)
        // Lane deltas: all 8 lanes have u = 2 (zigzag(2) = +1 accel)
        // Frame values:
        // t=0: p=10, v=0
        // t=1: v=1, p=11
        // t=2: v=2, p=13
        // t=3: v=3, p=16
        // ...
        let mut raw = vec![0u8; 13 * 4];
        raw[0..4].copy_from_slice(&13u32.to_le_bytes());
        raw[4] = 0; // b4
        raw[5] = 4; // b5
        raw[6] = 1; // b6
        raw[7] = 0;
        raw[8..12].copy_from_slice(&0.5f32.to_le_bytes()); // quantum = 0.5
        raw[12..16].copy_from_slice(&1.0f32.to_le_bytes()); // offset = 1.0
        // Prefix word: low 4 bits = 10 (0b1010), then unary 2 zeros + 1 one = 0b100 << 4 = 0x40 -> 0x4a
        raw[16..20].copy_from_slice(&0x4au32.to_le_bytes());
        for li in 0..8 {
            raw[20 + li * 4..24 + li * 4].copy_from_slice(&2u32.to_le_bytes());
        }

        let (vals, off_ok, anc_ok) = decode_class10_channel(9, &raw).expect("decode class10");
        assert!(off_ok && anc_ok);
        let expected_ints = [10, 11, 13, 16, 20, 25, 31, 38, 46];
        for (got, &exp) in vals.iter().zip(expected_ints.iter()) {
            let exp_f = 1.0 + (exp as f32) * 0.5;
            assert!((got - exp_f).abs() < 1e-6);
        }

        // Test glTF 2.0 (.glb) export on a synthetic CrAnimation
        let synth_anim = CrAnimation {
            offset: 0,
            hash: 0x1234,
            name: "synthetic_biped_test".into(),
            flags: 0,
            num_frames: 2,
            seq_frames: 2,
            duration: 1.0 / 30.0,
            signature: 1,
            max_block_size: 0,
            tracks: vec![
                AnimTrackDesc {
                    bone_id: 0x8133de19, // skel_pelvis
                    track_type: 0x98e1750c,
                    value_type: TrackValueType::Quaternion,
                    raw_value_type: 0,
                },
                AnimTrackDesc {
                    bone_id: 0x8133de19,
                    track_type: 0xf791a95f,
                    value_type: TrackValueType::Vector3,
                    raw_value_type: 2,
                },
            ],
            blocks: Vec::new(),
            track_frames: vec![
                DecodedTrackFrames::Quaternions(vec![[0.0, 0.0, 0.0, 1.0], [0.0, 0.7071068, 0.0, 0.7071068]]),
                DecodedTrackFrames::Vectors(vec![[0.0, 0.0, 1.0], [0.1, 0.2, 1.0]]),
            ],
        };
        let glb = export_cr_animation_to_glb(&synth_anim).expect("export glb");
        assert_eq!(&glb[0..4], b"glTF");
        assert_eq!(u32::from_le_bytes(glb[4..8].try_into().unwrap()), 2);
        assert_eq!(
            u32::from_le_bytes(glb[8..12].try_into().unwrap()) as usize,
            glb.len()
        );
    }
}
