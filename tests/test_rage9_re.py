# rage9-re by Ahmet Dedeler (https://github.com/Ahmet-Dedeler, https://ahmetdedeler.com)
# Source: https://github.com/Ahmet-Dedeler/rage9-re
# SPDX-License-Identifier: MIT OR Apache-2.0
# If you copy, vendor or port this file, keep this header and credit rage9-re in your README.
import json
import math
import os
import struct
import sys
import unittest
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import rage9_re as r9


class TestRage9ReSynthetic(unittest.TestCase):
    def test_joaat_known_hashes(self) -> None:
        self.assertEqual(r9.joaat_str("attributes"), 0x749DBB9E)
        self.assertEqual(r9.joaat_str("dataNodes"), 0x2260B8BE)
        self.assertEqual(r9.joaat_str("name"), 0xE6E17F14)
        self.assertEqual(r9.joaat_str("parentIndex"), 0xD89231BD)
        self.assertEqual(r9.joaat_str("childIndex"), 0x01296AED)
        self.assertEqual(r9.joaat_str("siblingIndex"), 0x881BF649)
        self.assertEqual(r9.joaat_str("previousSiblingIndex"), 0xF33047D9)
        self.assertEqual(r9.joaat_str("attributeStart"), 0x03341D59)
        self.assertEqual(r9.joaat_str("attributeCount"), 0x79661755)
        self.assertEqual(r9.joaat_str("valueHash"), 0x817ED7A4)
        self.assertEqual(r9.joaat_str("root"), 0xC090AFAD)
        self.assertEqual(r9.joaat_lower("bonerotation"), 0x98E1750C)
        self.assertEqual(r9.joaat_lower("bonetranslation"), 0xF791A95F)
        self.assertEqual(r9.joaat_lower("skel_pelvis"), 0x8133DE19)

    def test_rpf9_header_and_zlib_carving(self) -> None:
        buf = bytearray(0x100)
        buf[0:4] = b"9FPR"
        struct.pack_into("<IIIQIIHHIIII", buf, 4, 0x40, 0, 0, 0, 0x47A00, 0x150, 6, 1, 1, 0, 0, 0x10)
        hdrs = r9.Rpf9Header.scan_all(bytes(buf))
        self.assertEqual(len(hdrs), 1)
        self.assertEqual(hdrs[0].toc_end, 0x40)

        payload = b"<?xml version='1.0'?><test />"
        z = zlib.compress(payload)
        buf[0x40 : 0x40 + len(z)] = z
        streams = r9.carve_zlib_streams(bytes(buf), 0x40)
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0][2], payload)

    def test_synthetic_psin_and_script_dom_tree(self) -> None:
        psin_sec = bytearray()
        block_defs = [
            (0x00000016, 8),
            (0xAEB623D8, 12),
            (0x85B4C631, 32),
            (0xDE396FE2, 0x50),
            (0x01393259, 32),
        ]
        for bt, bsz in block_defs:
            psin_sec.extend(struct.pack("<IIQ", bt, bsz, 0xAAAAAAAAAAAAAAAA))
        psin_sec.extend(b"pppppppp")
        # Block 1: u64 (8B + 8B pad)
        psin_sec.extend(struct.pack("<QQ", 0xCAFEBABE12345678, 0))
        # Block 2: vec3 (12B + 4B pad)
        psin_sec.extend(struct.pack("<fffI", 10.0, -20.0, 30.5, 0))
        # Block 3: 2 attributes (32B)
        psin_sec.extend(struct.pack("<IIIBBxx", 0x1B60404D, 0, 99, 3, 1))
        psin_sec.extend(struct.pack("<IIIBBxx", 0x0C928991, 0, 0, 1, 1))
        # Block 4: root struct (0x50B)
        psin_sec.extend(struct.pack("<IIQ", 2, 2, 3))
        psin_sec.extend(struct.pack("<IIQ", 0, 0, 0))
        psin_sec.extend(struct.pack("<IIQ", 1, 1, 2))
        psin_sec.extend(struct.pack("<IIQ", 1, 1, 1))
        psin_sec.extend(struct.pack("<IIQ", 2, 2, 5))
        # Block 5: 2 nodes (32B)
        psin_sec.extend(struct.pack("<IHHHHHBB", 0xC090AFAD, 0xFFFF, 1, 0xFFFF, 0xFFFF, 0, 1, 1))
        psin_sec.extend(struct.pack("<IHHHHHBB", 0x1AECDE4D, 0, 0xFFFF, 0xFFFF, 0xFFFF, 1, 1, 1))

        lsch_sec = bytearray(32)
        struct.pack_into("<IIIIQIHH", lsch_sec, 0, 0xDE396FE2, 1, 0x300, 0, 0, 0x50, 0, 0)
        lsns_sec = struct.pack("<III", 1, 0x0101, 16) + (b"\xAA" * 16)
        lrsc_sec = bytearray(80)
        lrsc_sec[0:4] = b"0DRP"
        struct.pack_into("<I", lrsc_sec, 4, 0x7A)
        struct.pack_into("<I", lrsc_sec, 0x10, 4)
        struct.pack_into("<HHHH", lrsc_sec, 0x38, 1, 0, 5, 0)

        full = bytearray()
        for tag, body in [
            (b"PSIN", psin_sec),
            (b"LSCH", lsch_sec),
            (b"LENM", b""),
            (b"LSNS", lsns_sec),
            (b"LGID", b""),
            (b"LRSC", lrsc_sec),
        ]:
            full.extend(tag)
            full.extend(struct.pack(">I", len(body) + 8))
            full.extend(body)
        total_sz = len(full) + 20
        full.extend(b"CHKS")
        full.extend(struct.pack(">III", 20, total_sz, 0xDEADBEEF))
        full.extend(b"zppp")

        doc = r9.PsinDocument.parse(bytes(full))
        tree = r9.ScriptDataTree.from_psin(doc)
        self.assertEqual(len(tree.nodes), 2)
        xml = tree.to_xml()
        self.assertIn('<root id="99">', xml)
        self.assertIn('<tag Position="10.0000,-20.0000,30.5000" />', xml)

    def test_synthetic_object_graph(self) -> None:
        buf = bytearray(0xA0)
        struct.pack_into("<I", buf, 0x14, 2)
        struct.pack_into("<QQ", buf, 0x28, 0x40, 0x60)
        struct.pack_into("<IIQII", buf, 0x40, 0x12345678, 0, 0xC48AB516, 0x68, 0x71717171)
        struct.pack_into("<IIQIII", buf, 0x60, 0, 0, 0x14, 2, 2, 8)
        og = r9.ObjectGraph.parse(bytes(buf))
        self.assertEqual(len(og.records), 2)
        self.assertEqual(og.root_indices, [0])
        self.assertEqual(og.total_pointers, 1)

    def test_synthetic_class10_and_glb_export(self) -> None:
        raw = bytearray(13 * 4)
        struct.pack_into("<IBBBBff", raw, 0, 13, 0, 4, 1, 0, 0.5, 1.0)
        struct.pack_into("<I", raw, 16, 0x4A)
        for li in range(8):
            struct.pack_into("<I", raw, 20 + li * 4, 2)
        vals, off_ok, anc_ok = r9.decode_class10_channel(9, bytes(raw))
        self.assertTrue(off_ok)
        self.assertTrue(anc_ok)
        expected = [1.0 + x * 0.5 for x in [10, 11, 13, 16, 20, 25, 31, 38, 46]]
        for a, b in zip(vals, expected):
            self.assertAlmostEqual(a, b, places=6)

        glb = r9.export_animation_glb(
            "test_anim",
            2,
            1.0 / 30.0,
            [
                {
                    "bone_id": 0x8133DE19,
                    "value_type": 0,
                    "frames": [[0.0, 0.0, 0.0, 1.0], [0.0, 0.7071068, 0.0, 0.7071068]],
                }
            ],
        )
        self.assertEqual(glb[:4], b"glTF")
        ver, total_len, json_len, json_tag = struct.unpack_from("<IIII", glb, 4)
        self.assertEqual(ver, 2)
        self.assertEqual(total_len, len(glb))
        self.assertEqual(json_tag, 0x4E4F534A)
        gdict = json.loads(glb[20 : 20 + json_len].decode("utf-8"))
        self.assertEqual(gdict["nodes"][0]["name"], "skel_pelvis")
        # Accessor 0 max must exactly match the packed f32 timestamp in the BIN chunk
        bin_off = 20 + json_len + 8
        last_t = struct.unpack_from("<f", glb, bin_off + 4)[0]
        self.assertEqual(gdict["accessors"][0]["max"][0], last_t)

    def test_xml_bool_parity_and_cycle_guard(self) -> None:
        tree = r9.ScriptDataTree(
            attributes=[
                {"name_hash": 0x1B60404D, "name": "id", "value_hash": 0, "type": 4, "value": True, "valid": True}
            ],
            vectors=[],
            u64_table=[],
            nodes=[
                {"name_hash": 0xC090AFAD, "name": "root", "parent": 0xFFFF, "child": 1, "sibling": 0xFFFF, "prev_sibling": 0xFFFF, "attr_start": 0, "attr_count": 1, "valid": True},
                {"name_hash": 0x1AECDE4D, "name": "tag", "parent": 0, "child": 0, "sibling": 0xFFFF, "prev_sibling": 0xFFFF, "attr_start": 0, "attr_count": 0, "valid": True},
            ],
        )
        xml = tree.to_xml()
        self.assertIn('id="true"', xml)
        self.assertIn("</root>", xml)

    def test_malformed_inputs_and_glb_dedup(self) -> None:
        # Block index 0 must raise ValueError, not read blocks[-1]
        doc = r9.PsinDocument(0, 0x7A, [], [], [(0xDE396FE2, 0x50, b"\x00" * 0x50)], (0, 0, 0), b"", b"", 0, 0, b"zppp")
        with self.assertRaises(ValueError):
            r9.ScriptDataTree.from_psin(doc)

        # Class 5 val_bits == 0 must raise ValueError, not ZeroDivisionError
        blk = bytearray(0x20 + 20 + 22 + 8)
        coff = 0x20 + 20
        u10 = coff + 22 + 8
        struct.pack_into("<I", blk, 0x0C, 20)
        struct.pack_into("<I", blk, 0x10, u10)
        struct.pack_into("<H", blk, 0x16, 1)
        blk[0x1E] = 11
        struct.pack_into("<III", blk, 0x20, 1, 0, 0)
        struct.pack_into("<H", blk, coff + 5 * 2, 1)
        with self.assertRaises(ValueError):
            r9.decode_anim_block(bytes(blk), 0, 1)

        # Duplicate (node, path) channels deduplicated & infinite duration handled
        glb = r9.export_animation_glb(
            "dedup",
            2,
            float("inf"),
            [
                {"bone_id": 0, "track_type": 0xF5C3A5B6, "value_type": 2, "frames": [[9, 9, 9], [9, 9, 9]]},
                {"bone_id": 0, "track_type": 0xF791A95F, "value_type": 2, "frames": [[1, 2, 3], [4, 5, 6]]},
            ],
        )
        json_len = struct.unpack_from("<I", glb, 12)[0]
        gdict = json.loads(glb[20 : 20 + json_len].decode("utf-8"))
        self.assertEqual(len(gdict["animations"][0]["channels"]), 1)

        # 0 frames must raise ValueError
        with self.assertRaises(ValueError):
            r9.export_animation_glb("empty", 0, 1.0, [])


if __name__ == "__main__":
    unittest.main()
