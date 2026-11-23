# rage9-re by Ahmet Dedeler (https://github.com/Ahmet-Dedeler, https://ahmetdedeler.com)
# Source: https://github.com/Ahmet-Dedeler/rage9-re
# SPDX-License-Identifier: MIT OR Apache-2.0
# If you copy, vendor or port this file, keep this header and credit rage9-re in your README.
"""
Clean-room Python reference implementation of the RAGE9 decoder and inspector
for `script.rpf` (`PSIN` PSO v122 DOM trees & `0x71717171` Serialised Object Graph)
and `anim.rpf` (`crClipDictionary`, `crAnimation`, `crAnimSequence` channel codecs,
and JSON / glTF 2.0 `.glb` animation exporter).
"""

from __future__ import annotations
import dataclasses
import json
import math
import struct
import zlib
from typing import Dict, List, Optional, Tuple, Any

KNOWN_HASHES: Dict[int, str] = {
    # Script PSIN DOM schema & common node/attr names
    0x749DBB9E: "attributes",
    0x2260B8BE: "dataNodes",
    0xE6E17F14: "name",
    0xD89231BD: "parentIndex",
    0x01296AED: "childIndex",
    0x881BF649: "siblingIndex",
    0xF33047D9: "previousSiblingIndex",
    0x03341D59: "attributeStart",
    0x79661755: "attributeCount",
    0x817ED7A4: "valueHash",
    0x9303A5E5: "x",
    0x80950108: "y",
    0xB6606C9E: "z",
    0xC090AFAD: "root",
    0x1AECDE4D: "tag",
    0x1B60404D: "id",
    0x0C928991: "Position",
    0x4B621302: "Flags",
    # Animation track types (joaat lowercase)
    0x98E1750C: "bonerotation",
    0xF791A95F: "bonetranslation",
    0x2DEEFADD: "genericcontrol",
    0xF5C3A5B6: "generictranslation",
    0x6DDEF121: "cameratranslation",
    0x60D0644C: "firstpersoncameraweight",
    # Humanoid biped skeleton bone IDs (joaat lowercase)
    0x00000000: "mover",
    0x6686685C: "skel_root",
    0x8133DE19: "skel_pelvis",
    0x9E0FB7AF: "skel_spine_root",
    0x41E5D6A1: "skel_spine0",
    0xE07293B0: "skel_spine1",
    0xF242374F: "skel_spine2",
    0x2B3FA955: "skel_spine3",
    0xFB61FBB5: "skel_l_clavicle",
    0x3363E579: "skel_l_upperarm",
    0x052EA8FA: "skel_l_forearm",
    0xA49BBD43: "skel_l_hand",
    0xB13045DC: "skel_r_clavicle",
    0x0295D8F8: "skel_r_upperarm",
    0xB409B89D: "skel_r_forearm",
    0xB35ABA83: "skel_r_hand",
    0x3314F242: "skel_l_thigh",
    0xAF6F89C0: "skel_l_calf",
    0x3EC3BB37: "skel_l_foot",
    0x364E7F26: "skel_r_thigh",
    0xD1BD2D01: "skel_r_calf",
    0xAFCE3373: "skel_r_foot",
    0x3331F5D7: "ph_l_hand",
    0x81D2D8BE: "ph_r_hand",
    0xB14F571A: "ik_l_hand",
    0x04666F78: "ik_r_hand",
    0x8801C767: "ik_l_foot",
    0x0E3E181A: "ik_r_foot",
}


def joaat(data: bytes, seed: int = 0) -> int:
    h = seed & 0xFFFFFFFF
    for b in data:
        h = (h + b) & 0xFFFFFFFF
        h = (h + ((h << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h ^= h >> 6
    h = (h + ((h << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h ^= h >> 11
    h = (h + ((h << 15) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return h


def joaat_str(s: str, seed: int = 0) -> int:
    return joaat(s.encode("utf-8"), seed)


def joaat_lower(s: str, seed: int = 0) -> int:
    b = bytes(c + 32 if 65 <= c <= 90 else c for c in s.encode("utf-8"))
    return joaat(b, seed)


def align16(x: int) -> int:
    return (x + 15) & ~15


@dataclasses.dataclass
class Rpf9Header:
    offset: int
    toc_end: int
    field_08: int
    names_size: int
    salt: int
    field_18: int
    field_1c: int
    version_level: int
    field_22: int
    entry_count: int
    key_id: int
    flags: int
    field_30: int

    @classmethod
    def parse_at(cls, data: bytes, offset: int = 0) -> Optional["Rpf9Header"]:
        if offset < 0 or offset + 0x40 > len(data) or data[offset : offset + 4] != b"9FPR":
            return None
        toc_end, f08, names_sz, salt, f18, f1c, f20, f22, entries, key_id, flags, f30 = (
            struct.unpack_from("<IIIQIIHHIIII", data, offset + 4)
        )
        if f18 != 0x47A00 or f1c != 0x150 or f30 != 0x10:
            return None
        return cls(
            offset, toc_end, f08, names_sz, salt, f18, f1c, f20, f22, entries, key_id, flags, f30
        )

    @classmethod
    def scan_all(cls, data: bytes) -> List["Rpf9Header"]:
        out: List[Rpf9Header] = []
        pos = 0
        while True:
            idx = data.find(b"9FPR", pos)
            if idx == -1:
                break
            hdr = cls.parse_at(data, idx)
            if hdr is not None:
                out.append(hdr)
            pos = idx + 4
        return out


def is_zlib_header(data: bytes, off: int = 0) -> bool:
    if off + 2 > len(data):
        return False
    cmf, flg = data[off], data[off + 1]
    if (cmf & 0x0F) != 8 or (cmf >> 4) > 7 or (flg & 0x20) != 0:
        return False
    return ((cmf << 8) | flg) % 31 == 0


MAX_ZLIB_OUT = 64 * 1024 * 1024
MAX_ALLOC_SLOT_FLOATS = 64 * 1024 * 1024


def carve_zlib_streams(data: bytes, start_offset: int = 0) -> List[Tuple[int, int, bytes]]:
    streams: List[Tuple[int, int, bytes]] = []
    if start_offset < 0:
        raise ValueError("start_offset must be non-negative")
    mv = memoryview(data)
    pos = align16(start_offset)
    while pos + 6 <= len(data):
        if is_zlib_header(data, pos):
            dec = zlib.decompressobj()
            try:
                out = dec.decompress(mv[pos:], MAX_ZLIB_OUT + 1)
                if len(out) <= MAX_ZLIB_OUT and not dec.unconsumed_tail:
                    out += dec.flush()
                    if len(out) <= MAX_ZLIB_OUT:
                        consumed = len(data) - pos - len(dec.unused_data)
                        if consumed >= 6 and len(out) > 0 and dec.eof:
                            streams.append((pos, consumed, out))
                            pos = align16(pos + consumed)
                            continue
            except zlib.error:
                pass
        pos += 16
    return streams


def stitch_streams(streams: List[Tuple[int, int, bytes]]) -> List[Tuple[int, int, bytes]]:
    entries: List[Tuple[int, int, bytes]] = []
    i = 0
    while i < len(streams):
        off0, cons0, out0 = streams[i]
        buf = bytearray(out0)
        is_res = len(out0) >= 16 and (out0[0x0B] & 0xF0) == 0x50
        j = i + 1
        while j < len(streams):
            po, pc, pout = streams[j - 1]
            co, cc, cout = streams[j]
            if co != align16(po + pc):
                break
            if len(pout) == 65536 or (is_res and (co & 0xFFF) != 0x10):
                buf.extend(cout)
                j += 1
            else:
                break
        entries.append((off0, j - i, bytes(buf)))
        i = j
    return entries


# ---------------------------------------------------------------------------
# script.rpf: PSIN (PSO v122) & Compiled Binary-XML Script-Data DOM Tree
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class PsinDocument:
    root_block_index: int
    prd0_version: int
    structs: List[Tuple[int, int, int, int, List[Tuple[int, int, int, int, int, int]]]]
    enums: List[Tuple[int, int, List[Tuple[int, int]]]]
    blocks: List[Tuple[int, int, bytes]]
    lsns_header: Tuple[int, int, int]
    lsns_payload: bytes
    lgid: bytes
    chks_file_size: int
    chks_checksum: int
    chks_tag: bytes

    @classmethod
    def parse(cls, buf: bytes) -> "PsinDocument":
        if len(buf) < 16 or buf[:4] != b"PSIN":
            raise ValueError("Not a PSIN buffer")
        secs: Dict[bytes, bytes] = {}
        pos = 0
        while pos + 8 <= len(buf):
            tag = buf[pos : pos + 4]
            if not all(32 <= c < 127 for c in tag):
                raise ValueError(f"Invalid section tag {tag!r} at 0x{pos:x}")
            sz = struct.unpack_from(">I", buf, pos + 4)[0]
            if sz < 8 or pos + sz > len(buf):
                raise ValueError(f"Invalid section {tag!r} length {sz}")
            secs[tag] = buf[pos + 8 : pos + sz]
            pos += sz
        if pos != len(buf):
            raise ValueError("PSIN section walk did not close at EOF")

        if b"LRSC" not in secs:
            raise ValueError("Missing LRSC section")
        lrsc = secs[b"LRSC"]
        if len(lrsc) != 80 or lrsc[:4] != b"0DRP":
            raise ValueError("Invalid LRSC section")
        prd0_ver = struct.unpack_from("<I", lrsc, 4)[0]
        root_block_idx = struct.unpack_from("<I", lrsc, 0x10)[0]
        n_structs, n_enums, n_blocks, _ = struct.unpack_from("<HHHH", lrsc, 0x38)

        if b"LSCH" not in secs:
            raise ValueError("Missing LSCH section")
        lsch = secs[b"LSCH"]
        if len(lsch) < n_structs * 32:
            raise ValueError("LSCH section too short for struct headers")
        spos = 0
        raw_s = []
        for _ in range(n_structs):
            sh, ssig, sfl, _, _, ssz, _, nm = struct.unpack_from("<IIIIQIHH", lsch, spos)
            raw_s.append((sh, ssig, sfl, ssz, nm))
            spos += 32
        if spos + sum(x[4] for x in raw_s) * 16 != len(lsch):
            raise ValueError("LSCH length mismatch")
        structs = []
        for sh, ssig, sfl, ssz, nm in raw_s:
            membs = []
            for _ in range(nm):
                membs.append(struct.unpack_from("<IIBBHI", lsch, spos))
                spos += 16
            structs.append((sh, ssig, sfl, ssz, membs))

        if b"LENM" not in secs:
            raise ValueError("Missing LENM section")
        lenm = secs[b"LENM"]
        if len(lenm) < n_enums * 24:
            raise ValueError("LENM section too short")
        epos = 0
        raw_e = []
        for _ in range(n_enums):
            eh, esig, _, ecnt, _ = struct.unpack_from("<IIQII", lenm, epos)
            raw_e.append((eh, esig, ecnt))
            epos += 24
        enums = []
        for eh, esig, ecnt in raw_e:
            if epos + ecnt * 16 > len(lenm):
                raise ValueError("LENM enum values overflow")
            vals = [struct.unpack_from("<QQ", lenm, epos + k * 16) for k in range(ecnt)]
            epos += ecnt * 16
            enums.append((eh, esig, vals))
        if epos != len(lenm):
            raise ValueError("LENM length mismatch")

        if b"PSIN" not in secs:
            raise ValueError("Missing PSIN section")
        psin = secs[b"PSIN"]
        if len(psin) < n_blocks * 16:
            raise ValueError("PSIN block table overflow")
        b_hdrs = [struct.unpack_from("<IIQ", psin, bi * 16)[:2] for bi in range(n_blocks)]
        cur_f = align16(8 + n_blocks * 16)
        blocks = []
        for bt, bsz in b_hdrs:
            rel = cur_f - 8
            if rel + bsz > len(psin):
                raise ValueError("PSIN block overflow")
            blocks.append((bt, bsz, psin[rel : rel + bsz]))
            cur_f = align16(cur_f + bsz)
        if cur_f - 8 != len(psin):
            raise ValueError("PSIN end mismatch")

        if b"LSNS" not in secs:
            raise ValueError("Missing LSNS section")
        lsns = secs[b"LSNS"]
        if len(lsns) < 12:
            raise ValueError("LSNS section shorter than 12-byte header")
        c0, f1, tlen = struct.unpack_from("<III", lsns, 0)
        if tlen != len(lsns) - 12:
            raise ValueError("LSNS tail_len mismatch")

        if b"CHKS" not in secs:
            raise ValueError("Missing CHKS section")
        chks = secs[b"CHKS"]
        if len(chks) != 12:
            raise ValueError("CHKS section must be 12 bytes")
        csz, cval = struct.unpack_from(">II", chks, 0)
        if csz != len(buf):
            raise ValueError("CHKS file size mismatch")

        return cls(
            root_block_idx,
            prd0_ver,
            structs,
            enums,
            blocks,
            (c0, f1, tlen),
            lsns[12:],
            secs.get(b"LGID", b""),
            csz,
            cval,
            chks[8:12],
        )


@dataclasses.dataclass
class ScriptDataTree:
    attributes: List[Dict[str, Any]]
    vectors: List[Tuple[float, float, float]]
    u64_table: List[int]
    nodes: List[Dict[str, Any]]

    @classmethod
    def from_psin(cls, doc: PsinDocument) -> "ScriptDataTree":
        def get_block(idx_1based: int, label: str) -> Tuple[int, int, bytes]:
            if idx_1based < 1 or idx_1based > len(doc.blocks):
                raise ValueError(f"Invalid {label} block index {idx_1based}")
            return doc.blocks[idx_1based - 1]

        r_type, r_sz, r_data = get_block(doc.root_block_index, "root")
        if r_type != 0xDE396FE2 or len(r_data) != 0x50:
            raise ValueError(f"Unsupported root struct 0x{r_type:08x}")
        arrs = []
        for ai in range(5):
            cnt, cap, ref = struct.unpack_from("<IIQ", r_data, ai * 16)
            arrs.append((cnt, ref & 0xFFF, ref >> 20))
        (n_attr, b_attr, o_attr), _, (n_vec, b_vec, o_vec), (n_u64, b_u64, o_u64), (
            n_node,
            b_node,
            o_node,
        ) = arrs

        vectors: List[Tuple[float, float, float]] = []
        if n_vec > 0:
            vb = get_block(b_vec, "vector")[2]
            if o_vec + n_vec * 12 > len(vb):
                raise ValueError("Vector array out of bounds")
            vectors = [struct.unpack_from("<fff", vb, o_vec + k * 12) for k in range(n_vec)]

        u64_table: List[int] = []
        if n_u64 > 0:
            ub = get_block(b_u64, "u64")[2]
            if o_u64 + n_u64 * 8 > len(ub):
                raise ValueError("u64 array out of bounds")
            u64_table = [struct.unpack_from("<Q", ub, o_u64 + k * 8)[0] for k in range(n_u64)]

        attributes: List[Dict[str, Any]] = []
        if n_attr > 0:
            ab = get_block(b_attr, "attribute")[2]
            if o_attr + n_attr * 16 > len(ab):
                raise ValueError("Attribute array out of bounds")
            for k in range(n_attr):
                nh, vh, raw_v, ev, bl = struct.unpack_from("<IIIBB", ab, o_attr + k * 16)
                if ev == 0:
                    val: Any = f"str#{raw_v}"
                elif ev == 1:
                    if raw_v >= len(vectors):
                        raise ValueError(f"Vector index {raw_v} >= {len(vectors)}")
                    val = list(vectors[raw_v])
                elif ev == 2:
                    val = struct.unpack("<f", struct.pack("<I", raw_v))[0]
                elif ev == 3:
                    val = struct.unpack("<i", struct.pack("<I", raw_v))[0]
                elif ev == 4:
                    val = bool(raw_v)
                elif ev == 5:
                    if raw_v >= len(u64_table):
                        raise ValueError(f"u64 index {raw_v} >= {len(u64_table)}")
                    val = u64_table[raw_v]
                else:
                    raise ValueError(f"Unknown attribute enum {ev}")
                attributes.append(
                    {
                        "name_hash": nh,
                        "name": KNOWN_HASHES.get(nh, f"attr_{nh:08x}"),
                        "value_hash": vh,
                        "type": ev,
                        "value": val,
                        "valid": bool(bl),
                    }
                )

        nodes: List[Dict[str, Any]] = []
        if n_node > 0:
            nb = get_block(b_node, "node")[2]
            if o_node + n_node * 16 > len(nb):
                raise ValueError("Node array out of bounds")
            for k in range(n_node):
                nh, par, ch, sib, psib, astart, acnt, nbl = struct.unpack_from(
                    "<IHHHHHBB", nb, o_node + k * 16
                )
                for link in (par, ch, sib, psib):
                    if link != 0xFFFF and link >= n_node:
                        raise ValueError("Node link out of bounds")
                if acnt > 0 and astart + acnt > n_attr:
                    raise ValueError("Node attribute range out of bounds")
                nodes.append(
                    {
                        "name_hash": nh,
                        "name": KNOWN_HASHES.get(nh, f"node_{nh:08x}"),
                        "parent": par,
                        "child": ch,
                        "sibling": sib,
                        "prev_sibling": psib,
                        "attr_start": astart,
                        "attr_count": acnt,
                        "valid": bool(nbl),
                    }
                )

        return cls(attributes, vectors, u64_table, nodes)

    def to_xml(self) -> str:
        if not self.nodes:
            return ""
        lines: List[str] = []
        visited: set[int] = set()

        def visit(idx: int, depth: int) -> None:
            if idx < 0 or idx >= len(self.nodes) or idx in visited:
                return
            visited.add(idx)
            n = self.nodes[idx]
            ind = "  " * depth
            tag = n["name"]
            astr = ""
            if n["attr_count"] > 0:
                astart = n["attr_start"]
                aend = astart + n["attr_count"]
                for a in self.attributes[astart:aend]:
                    v = a["value"]
                    if isinstance(v, list):
                        v_fmt = ",".join(f"{x:.4f}" for x in v)
                    elif isinstance(v, bool):
                        v_fmt = "true" if v else "false"
                    elif isinstance(v, float):
                        v_fmt = f"{v:.6f}"
                    elif a["type"] == 5:
                        v_fmt = f"0x{v:016x}"
                    else:
                        v_fmt = str(v)
                    astr += f' {a["name"]}="{v_fmt}"'
            if n["child"] == 0xFFFF:
                lines.append(f"{ind}<{tag}{astr} />")
            else:
                lines.append(f"{ind}<{tag}{astr}>")
                c = n["child"]
                guard = 0
                while c != 0xFFFF and c < len(self.nodes) and guard < len(self.nodes):
                    visit(c, depth + 1)
                    c = self.nodes[c]["sibling"]
                    guard += 1
                lines.append(f"{ind}</{tag}>")

        visit(0, 0)
        return "\n".join(lines) + "\n"


@dataclasses.dataclass
class ObjectGraph:
    records: List[Dict[str, Any]]
    root_indices: List[int]
    total_pointers: int

    PTR_TAG = 0x71717171

    @classmethod
    def parse(cls, buf: bytes) -> "ObjectGraph":
        if len(buf) < 0x30:
            raise ValueError("ObjectGraph buffer too short")
        cnt = struct.unpack_from("<I", buf, 0x14)[0]
        if cnt == 0 or 0x28 + cnt * 8 > len(buf):
            raise ValueError("Invalid ObjectGraph record count")
        offsets = list(struct.unpack_from(f"<{cnt}Q", buf, 0x28))
        if offsets[0] != align16(0x28 + cnt * 8):
            raise ValueError("ObjectGraph table end mismatch")
        for i, off in enumerate(offsets):
            if (off & 15) != 0 or off >= len(buf):
                raise ValueError(f"Unaligned or OOB record offset 0x{off:x}")
            if i > 0 and off <= offsets[i - 1]:
                raise ValueError("Non-monotonic record offsets")
        off_to_idx = {o: i for i, o in enumerate(offsets)}

        records: List[Dict[str, Any]] = []
        targeted = set()
        total_ptrs = 0

        for i, off in enumerate(offsets):
            end = offsets[i + 1] if i + 1 < cnt else len(buf)
            sz = end - off
            if sz < 0x20 or (sz & 15) != 0:
                raise ValueError(f"Invalid record size {sz}")
            rid = struct.unpack_from("<I", buf, off)[0]
            th = struct.unpack_from("<Q", buf, off + 8)[0]
            arr_info = None
            if th == 0x14:
                acnt, acnt2, astride = struct.unpack_from("<III", buf, off + 0x10)
                if acnt != acnt2 or align16(0x30 + acnt * astride) != sz:
                    raise ValueError("Array record size mismatch")
                arr_info = (acnt, astride)
            ptrs = []
            for rel in range(0x10, sz, 8):
                t_p8, tag = struct.unpack_from("<II", buf, off + rel)
                if tag == cls.PTR_TAG:
                    if t_p8 < 8 or (t_p8 - 8) not in off_to_idx:
                        raise ValueError(f"Pointer to non-record offset 0x{t_p8 - 8:x}")
                    t_idx = off_to_idx[t_p8 - 8]
                    ptrs.append((rel, t_idx))
                    targeted.add(t_idx)
                    total_ptrs += 1
            records.append(
                {
                    "index": i,
                    "offset": off,
                    "size": sz,
                    "root_id": rid,
                    "type_hash": th,
                    "array_info": arr_info,
                    "pointers": ptrs,
                }
            )
        roots = [i for i in range(cnt) if i not in targeted]
        return cls(records, roots, total_ptrs)


# ---------------------------------------------------------------------------
# anim.rpf: crAnimSequence channel codecs & glTF 2.0 Exporter
# ---------------------------------------------------------------------------


def zigzag_decode(u: int) -> int:
    return (u >> 1) ^ -(u & 1)


def _wrap_i32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def sys_ptr(buf: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 8 > len(buf):
        return None
    v = struct.unpack_from("<Q", buf, off)[0]
    if (v >> 28) == 5:
        p = v & 0x0FFFFFFF
        if p < len(buf):
            return p
    return None


def read_cstr(buf: bytes, off: Optional[int]) -> Optional[str]:
    if off is None or off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\x00", off)
    if end == -1:
        return None
    return buf[off:end].decode("utf-8", errors="replace")


def decode_class10_channel(num_frames: int, raw: bytes) -> Tuple[List[float], bool, bool]:
    if num_frames < 0:
        raise ValueError("num_frames must be non-negative")
    if len(raw) < 16:
        raise ValueError("Class 10 channel shorter than 16-byte header")
    dw = struct.unpack_from("<I", raw, 0)[0]
    if dw < 4 or dw * 4 > len(raw):
        raise ValueError("Class 10 dword count out of range")
    b4, b5, b6, _ = raw[4:8]
    if b4 > 32 or b5 > 32:
        raise ValueError(f"Class 10 prefix bit widths out of range (b4={b4}, b5={b5})")
    if 4 + 8 * b6 > dw:
        raise ValueError("Class 10 lane dwords exceed total dwords")
    q, o = struct.unpack_from("<ff", raw, 8)
    n_pref = dw - 4 - 8 * b6
    pref = int.from_bytes(raw[16 : 16 + n_pref * 4], "little")
    lw = struct.unpack_from(f"<{8*b6}I", raw, 16 + n_pref * 4)
    lanes = [sum(lw[s * 8 + li] << (32 * s) for s in range(b6)) for li in range(8)]

    n_super = (num_frames + 63) // 64
    offsets = [((pref >> (i * b4)) & ((1 << b4) - 1)) if b4 > 0 else 0 for i in range(n_super)]
    anchors = [
        _wrap_i32(((pref >> (n_super * b4 + i * b5)) & ((1 << b5) - 1)) if b5 > 0 else 0)
        for i in range(n_super)
    ]
    skip = n_super * (b4 + b5)

    rem = pref >> skip
    n_groups = (max(0, num_frames - 1) + 7) // 8
    runs: List[int] = []
    p = 0
    while (rem >> p) != 0:
        z = 0
        while ((rem >> p) & 1) == 0:
            z += 1
            p += 1
        p += 1
        runs.append(z)

    cum = [sum(runs[: i * 8]) for i in range(n_super)]
    off_ok = (cum == offsets) and (len(runs) == n_groups)

    deltas: List[int] = []
    bp = 0
    for bw in runs:
        if bw > 32:
            raise ValueError(f"Class 10 delta bit width {bw} > 32")
        for li in range(8):
            u = ((lanes[li] >> bp) & ((1 << bw) - 1)) if bw > 0 else 0
            deltas.append(zigzag_decode(u))
        bp += bw

    ints = [0] * num_frames
    anc_ok = True
    for sb in range(n_super):
        t0 = sb * 64
        cp = anchors[sb]
        cv = 0
        if t0 < num_frames:
            ints[t0] = cp
        for t in range(t0 + 1, min(num_frames, t0 + 64)):
            d = deltas[t - 1] if (t - 1) < len(deltas) else 0
            cv = _wrap_i32(cv + d)
            cp = _wrap_i32(cp + cv)
            ints[t] = cp
        if sb + 1 < n_super:
            d = deltas[t0 + 63] if (t0 + 63) < len(deltas) else 0
            cv = _wrap_i32(cv + d)
            cp = _wrap_i32(cp + cv)
            if cp != anchors[sb + 1]:
                anc_ok = False

    return [o + x * q for x in ints], off_ok, anc_ok


def decode_anim_block(buf: bytes, blk_off: int, num_tracks: int) -> Dict[str, Any]:
    if blk_off < 0 or blk_off + 0x20 > len(buf):
        raise ValueError("Anim block header out of bounds")
    sig, u04, u08, doff, u10, u14, nf, st, h1a, bpf, b1e, b1f = struct.unpack_from(
        "<IIIIIHHHHHBB", buf, blk_off
    )
    if b1e != 11:
        raise ValueError(f"Expected 11 channel classes, got {b1e}")
    desc_end = 0x20 + doff
    coff = desc_end + nf * st
    if blk_off + coff + 22 > len(buf) or blk_off + u10 > len(buf) or u10 < coff + 22:
        raise ValueError("Anim block tail counts out of bounds")
    cs = struct.unpack_from("<11H", buf, blk_off + coff)
    ip = coff + 22
    idxs: Dict[int, Tuple[int, ...]] = {}
    for ci, c in enumerate(cs):
        if c > 0:
            padded_bytes = ((c + 3) & ~3) * 2
            if ip + padded_bytes > u10:
                raise ValueError("Channel index table exceeds u10")
            idxs[ci] = struct.unpack_from(f"<{c}H", buf, blk_off + ip)
            ip += padded_bytes
    if ip != u10:
        raise ValueError("Channel index table end mismatch")

    max_sl = max((max(v) for v in idxs.values()), default=0)
    num_slots = max(num_tracks * 4, (max_sl + 4) & ~3)
    if num_slots * nf > MAX_ALLOC_SLOT_FLOATS:
        raise ValueError(f"Anim block slot buffer too large ({num_slots} slots x {nf} frames)")
    slots: List[List[float]] = [[0.0] * nf for _ in range(num_slots)]

    pos = 0x20

    def check_desc(need: int) -> int:
        if pos + need > desc_end:
            raise ValueError(f"Channel descriptor at 0x{pos:x} (+{need}) exceeds data_off 0x{desc_end:x}")
        return pos + need

    for sl in idxs.get(0, ()):
        nxt = check_desc(12)
        x, y, z = struct.unpack_from("<fff", buf, blk_off + pos)
        pos = nxt
        w = math.sqrt(max(0.0, 1.0 - (x * x + y * y + z * z)))
        if sl + 3 < num_slots:
            slots[sl] = [x] * nf
            slots[sl + 1] = [y] * nf
            slots[sl + 2] = [z] * nf
            slots[sl + 3] = [w] * nf

    for sl in idxs.get(1, ()):
        nxt = check_desc(12)
        x, y, z = struct.unpack_from("<fff", buf, blk_off + pos)
        pos = nxt
        if sl + 2 < num_slots:
            slots[sl] = [x] * nf
            slots[sl + 1] = [y] * nf
            slots[sl + 2] = [z] * nf

    for sl in idxs.get(2, ()):
        nxt = check_desc(4)
        v = struct.unpack_from("<f", buf, blk_off + pos)[0]
        pos = nxt
        if sl < num_slots:
            slots[sl] = [v] * nf

    q4 = []
    for _ in range(cs[4]):
        nxt = check_desc(12)
        nb, q, o = struct.unpack_from("<Iff", buf, blk_off + pos)
        if nb > 32:
            raise ValueError(f"Class 4 nbits {nb} > 32")
        q4.append((nb, q, o))
        pos = nxt
    if sum(x[0] for x in q4) != bpf:
        raise ValueError("Class 4 bit budget mismatch")

    c5 = []
    c5_bits_sum = 0
    for _ in range(cs[5]):
        check_desc(20)
        w0, w1, w2, q, o = struct.unpack_from("<IIIff", buf, blk_off + pos)
        if w1 == 0 or w1 > 32:
            raise ValueError(f"Invalid Class 5 val_bits {w1}")
        if w0 > 32:
            raise ValueError(f"Invalid Class 5 idx_bits {w0}")
        nxt = check_desc(20 + w2 * 4)
        li = int.from_bytes(buf[blk_off + pos + 20 : blk_off + nxt], "little")
        n_lut = (w2 * 32) // w1
        lut = [o + ((li >> (i * w1)) & ((1 << w1) - 1)) * q for i in range(n_lut)]
        c5.append((w0, lut))
        c5_bits_sum += w0
        pos = nxt

    c10_verified = 0
    for sl in idxs.get(10, ()):
        check_desc(4)
        dw = struct.unpack_from("<I", buf, blk_off + pos)[0]
        nxt = check_desc(dw * 4)
        vals, off_ok, anc_ok = decode_class10_channel(nf, buf[blk_off + pos : blk_off + nxt])
        if not (off_ok and anc_ok):
            raise ValueError("Class 10 superblock verification failed")
        c10_verified += 1
        if sl < num_slots:
            slots[sl] = vals
        pos = nxt

    if pos != desc_end:
        raise ValueError("Channel descriptor end mismatch")

    if q4 or c5:
        if bpf + c5_bits_sum > st * 8:
            raise ValueError(f"Per-frame bits ({bpf + c5_bits_sum}) exceed frame_stride ({st * 8} bits)")
        fbase = blk_off + desc_end
        for fi in range(nf):
            fint = int.from_bytes(buf[fbase + fi * st : fbase + (fi + 1) * st], "little")
            bp = 0
            for qi, (nb, q, o) in enumerate(q4):
                sl = idxs[4][qi]
                if sl < num_slots:
                    slots[sl][fi] = o + ((fint >> bp) & ((1 << nb) - 1)) * q
                bp += nb
            for ci5, (w0, lut) in enumerate(c5):
                u = (fint >> bp) & ((1 << w0) - 1)
                sl = idxs[5][ci5]
                if sl < num_slots and u < len(lut):
                    slots[sl][fi] = lut[u]
                bp += w0

    for sl in idxs.get(7, ()):
        base = sl & ~3
        comp = sl & 3
        if base + 3 < num_slots:
            for fi in range(nf):
                a, b_v, c = slots[base][fi], slots[base + 1][fi], slots[base + 2][fi]
                r = math.sqrt(max(0.0, 1.0 - (a * a + b_v * b_v + c * c)))
                if comp == 0:
                    q_arr = [r, a, b_v, c]
                elif comp == 1:
                    q_arr = [a, r, b_v, c]
                elif comp == 2:
                    q_arr = [a, b_v, r, c]
                else:
                    q_arr = [a, b_v, c, r]
                nrm = math.sqrt(sum(x * x for x in q_arr))
                if nrm > 1e-8:
                    q_arr = [x / nrm for x in q_arr]
                for c_i in range(4):
                    slots[base + c_i][fi] = q_arr[c_i]

    for sl in idxs.get(8, ()):
        base = sl & ~3
        if base + 3 < num_slots:
            for fi in range(nf):
                q_arr = [slots[base + c_i][fi] for c_i in range(4)]
                nrm = math.sqrt(sum(x * x for x in q_arr))
                if nrm > 1e-8:
                    for c_i in range(4):
                        slots[base + c_i][fi] = q_arr[c_i] / nrm

    return {
        "offset": blk_off,
        "signature": sig,
        "num_frames": nf,
        "frame_stride": st,
        "bits_per_frame": bpf,
        "class_counts": cs,
        "class10_verified": c10_verified,
        "slots": slots,
    }


def _sanitize_quat(q: Any) -> Tuple[float, float, float, float]:
    vals = [float(x) for x in q]
    if len(vals) != 4 or not all(math.isfinite(x) for x in vals):
        return (0.0, 0.0, 0.0, 1.0)
    nrm = math.sqrt(sum(x * x for x in vals))
    if not math.isfinite(nrm) or nrm <= 1e-8:
        return (0.0, 0.0, 0.0, 1.0)
    return (vals[0] / nrm, vals[1] / nrm, vals[2] / nrm, vals[3] / nrm)


def _sanitize_vec3(v: Any) -> Tuple[float, float, float]:
    vals = [float(x) for x in v]
    return tuple(x if math.isfinite(x) else 0.0 for x in vals[:3])  # type: ignore[return-value]


def export_animation_glb(
    name: str,
    num_frames: int,
    duration: float,
    tracks: List[Dict[str, Any]],
) -> bytes:
    if num_frames <= 0:
        raise ValueError("Animation has 0 frames")
    if num_frames > 1 and math.isfinite(duration) and duration > 0:
        dt = duration / (num_frames - 1)
        if not (math.isfinite(dt) and dt > 0):
            dt = 1.0 / 30.0
    else:
        dt = 1.0 / 30.0

    bone_ids: List[int] = []
    for t in tracks:
        if t["value_type"] in (0, 2) and t["bone_id"] not in bone_ids:
            bone_ids.append(t["bone_id"])
    if not bone_ids:
        bone_ids.append(0)

    bin_buf = bytearray()
    max_t = 0.0
    for fi in range(num_frames):
        packed = struct.pack("<f", fi * dt)
        bin_buf.extend(packed)
        max_t = struct.unpack("<f", packed)[0]

    buffer_views = [{"buffer": 0, "byteOffset": 0, "byteLength": num_frames * 4}]
    accessors: List[Dict[str, Any]] = [
        {
            "bufferView": 0,
            "componentType": 5126,
            "count": num_frames,
            "type": "SCALAR",
            "min": [0.0],
            "max": [max_t],
        }
    ]
    samplers = []
    channels = []

    ordered = sorted(
        tracks,
        key=lambda t: 0 if t.get("track_type") in (0x98E1750C, 0xF791A95F) else 1,
    )
    seen_targets: set[Tuple[int, str]] = set()

    for t in ordered:
        if t["value_type"] not in (0, 2):
            continue
        node_idx = bone_ids.index(t["bone_id"])
        path = "rotation" if t["value_type"] == 0 else "translation"
        if (node_idx, path) in seen_targets:
            continue
        frames = t["frames"]
        if len(frames) != num_frames:
            raise ValueError(f"Track frame count {len(frames)} != num_frames {num_frames}")
        seen_targets.add((node_idx, path))
        boff = len(bin_buf)
        if t["value_type"] == 0:
            for q in frames:
                bin_buf.extend(struct.pack("<ffff", *_sanitize_quat(q)))
            blen = len(frames) * 16
            atype = "VEC4"
        else:
            for v in frames:
                bin_buf.extend(struct.pack("<fff", *_sanitize_vec3(v)))
            blen = len(frames) * 12
            atype = "VEC3"

        bv_idx = len(buffer_views)
        acc_idx = len(accessors)
        samp_idx = len(samplers)
        buffer_views.append({"buffer": 0, "byteOffset": boff, "byteLength": blen})
        accessors.append(
            {"bufferView": bv_idx, "componentType": 5126, "count": len(frames), "type": atype}
        )
        samplers.append({"input": 0, "interpolation": "LINEAR", "output": acc_idx})
        channels.append({"sampler": samp_idx, "target": {"node": node_idx, "path": path}})

    while len(bin_buf) & 3:
        bin_buf.append(0)

    nodes = [{"name": KNOWN_HASHES.get(bid, f"bone_{bid:08x}")} for bid in bone_ids]
    gltf: Dict[str, Any] = {
        "asset": {"version": "2.0", "generator": "rage9-re"},
        "scene": 0,
        "scenes": [{"nodes": list(range(len(nodes)))}],
        "nodes": nodes,
        "buffers": [{"byteLength": len(bin_buf)}],
        "bufferViews": buffer_views,
        "accessors": accessors,
    }
    if channels:
        gltf["animations"] = [{"name": name, "samplers": samplers, "channels": channels}]
    jb = json.dumps(gltf, separators=(",", ":"), allow_nan=False).encode("utf-8")
    while len(jb) & 3:
        jb += b" "

    total_len = 12 + 8 + len(jb) + 8 + len(bin_buf)
    out = bytearray()
    out.extend(b"glTF")
    out.extend(struct.pack("<II", 2, total_len))
    out.extend(struct.pack("<II", len(jb), 0x4E4F534A))
    out.extend(jb)
    out.extend(struct.pack("<II", len(bin_buf), 0x004E4942))
    out.extend(bin_buf)
    return bytes(out)
