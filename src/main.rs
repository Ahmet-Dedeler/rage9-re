// rage9-re by Ahmet Dedeler (https://github.com/Ahmet-Dedeler, https://ahmetdedeler.com)
// Source: https://github.com/Ahmet-Dedeler/rage9-re
// SPDX-License-Identifier: MIT OR Apache-2.0
// If you copy, vendor or port this file, keep this header and credit rage9-re in your README.
use rage9_re::anim::{CrClipDictionary, DecodedTrackFrames};
use rage9_re::rpf9::{carve_zlib_streams, stitch_streams, EntryKind, Rpf9Header};
use rage9_re::script::{ObjectGraph, PsinDocument, ScriptDataTree};
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom};

fn cmd_inspect_script(path: &str, dump_xml_idx: Option<usize>, dump_og_root: Option<usize>) {
    let data = fs::read(path).expect("Failed to read script.rpf");
    println!("=== RAGE9 script.rpf Inspector ===");
    println!("File: {path} ({} bytes)", data.len());

    let headers = Rpf9Header::scan_all(&data);
    println!("Found {} RPF9 (9FPR) headers:", headers.len());
    for h in &headers {
        println!(
            "  @ 0x{:06x}: toc_end=0x{:x} names_sz=0x{:x} entries={} key_id=0x{:08x} flags=0x{:08x} lvl={}",
            h.offset, h.toc_end, h.names_size, h.entry_count, h.key_id, h.flags, h.version_level
        );
    }

    let start_off = headers
        .first()
        .map_or(0, |h| h.offset.saturating_add(h.toc_end as usize));
    let streams = carve_zlib_streams(&data, start_off);
    let entries = stitch_streams(&streams);
    println!(
        "Carved {} zlib streams -> {} stitched entries",
        streams.len(),
        entries.len()
    );

    let mut psin_total = 0usize;
    let mut psin_ok = 0usize;
    let mut dom_ok = 0usize;
    let mut total_nodes = 0usize;
    let mut total_attrs = 0usize;
    let mut total_vecs = 0usize;
    let mut total_u64s = 0usize;

    for (idx, e) in entries.iter().enumerate() {
        match e.kind {
            EntryKind::ObjectGraph => match ObjectGraph::parse(&e.data) {
                Ok(og) => {
                    let arr_cnt = og.records.iter().filter(|r| r.array_info.is_some()).count();
                    println!(
                        "  [Entry #{idx} @ 0x{:06x}] Serialised ObjectGraph: {} B ({} streams), {} records, {} arrays, {} pointers, {} root trees",
                        e.offset,
                        e.data.len(),
                        e.stream_count,
                        og.records.len(),
                        arr_cnt,
                        og.total_pointers,
                        og.root_indices.len()
                    );
                    if let Some(ri) = dump_og_root {
                        if let Some(&rec_idx) = og.root_indices.get(ri) {
                            println!(
                                "\n--- Disassembly of ObjectGraph Root #{ri} (rec#{rec_idx}) ---"
                            );
                            print!("{}", og.disassemble_tree(rec_idx, 4));
                        }
                    }
                }
                Err(err) => {
                    eprintln!(
                        "  [Entry #{idx} @ 0x{:06x}] ObjectGraph parse error: {err}",
                        e.offset
                    );
                }
            },
            EntryKind::Psin => {
                psin_total += 1;
                if let Ok(doc) = PsinDocument::parse(&e.data) {
                    psin_ok += 1;
                    if let Ok(tree) = ScriptDataTree::from_psin(&doc) {
                        dom_ok += 1;
                        total_nodes += tree.nodes.len();
                        total_attrs += tree.attributes.len();
                        total_vecs += tree.vectors.len();
                        total_u64s += tree.u64_table.len();
                        if dump_xml_idx == Some(psin_total - 1) {
                            println!(
                                "\n--- Reconstructed XML for PSIN #{} @ 0x{:06x} ---",
                                psin_total - 1,
                                e.offset
                            );
                            print!("{}", tree.to_xml());
                        }
                    }
                }
            }
            other => {
                println!(
                    "  [Entry #{idx} @ 0x{:06x}] {:?}: {} B",
                    e.offset,
                    other,
                    e.data.len()
                );
            }
        }
    }

    println!(
        "PSIN containers parsed: {psin_ok}/{psin_total} | Script DOM trees verified: {dom_ok}/{psin_total}"
    );
    println!(
        "DOM totals: nodes={total_nodes}, attributes={total_attrs}, vectors={total_vecs}, u64_hashes={total_u64s}"
    );
}

fn cmd_inspect_anim(path: &str, export_glb_out: Option<&str>) {
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("Failed to open {path}: {err}");
            std::process::exit(1);
        }
    };
    let file_len = match f.metadata() {
        Ok(m) => m.len(),
        Err(err) => {
            eprintln!("Failed to stat {path}: {err}");
            std::process::exit(1);
        }
    };
    let mut head = [0u8; 0x40];
    if file_len < 0x40 || f.read_exact(&mut head).is_err() {
        eprintln!("File {path} is shorter than 64 bytes ({file_len} bytes)");
        std::process::exit(1);
    }

    if &head[0..4] != b"9FPR" {
        // Direct carved CrClipDictionary binary
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(err) => {
                eprintln!("Failed to read {path}: {err}");
                std::process::exit(1);
            }
        };
        let cd = match CrClipDictionary::parse(&data) {
            Ok(cd) => cd,
            Err(err) => {
                eprintln!("Failed to parse CrClipDictionary: {err}");
                std::process::exit(1);
            }
        };
        println!(
            "Parsed CrClipDictionary '{}': {} clips, {} animations",
            cd.name,
            cd.clips.len(),
            cd.animations.len()
        );
        if let Some(out_path) = export_glb_out {
            match cd.export_animation_glb(0) {
                Ok(glb) => {
                    if let Err(err) = fs::write(out_path, &glb) {
                        eprintln!("Failed to write GLB to {out_path}: {err}");
                        std::process::exit(1);
                    }
                    println!("Exported glTF 2.0 binary ({} bytes) to {out_path}", glb.len());
                }
                Err(err) => {
                    eprintln!("Failed to export GLB: {err}");
                    std::process::exit(1);
                }
            }
        }
        return;
    }

    let hdr = match Rpf9Header::parse_at(&head, 0) {
        Some(h) => h,
        None => {
            eprintln!("Invalid RPF9 header in {path}");
            std::process::exit(1);
        }
    };
    println!("=== RAGE9 anim.rpf Windowed Inspector ===");
    println!(
        "File: {path} ({} bytes) | toc_end=0x{:x} entries={} key_id=0x{:08x}",
        file_len, hdr.toc_end, hdr.entry_count, hdr.key_id
    );

    let win_offsets: [u64; 5] = [
        ((hdr.toc_end as u64) + 0xfff) & !0xfff,
        0x2000_0000,
        0x4000_0000,
        0x8000_0000,
        0xc000_0000,
    ];
    let win_size: u64 = 4 * 1024 * 1024;

    let mut total_clip_dicts = 0usize;
    let mut total_clips = 0usize;
    let mut total_anims = 0usize;
    let mut total_blocks = 0usize;
    let mut total_c10 = 0usize;
    let mut total_quats = 0usize;
    let mut max_quat_err = 0.0f32;
    let mut exported = false;

    for &woff in &win_offsets {
        if woff >= file_len {
            continue;
        }
        let read_len = win_size.min(file_len - woff) as usize;
        let mut buf = vec![0u8; read_len];
        if let Err(err) = f.seek(SeekFrom::Start(woff)).and_then(|_| f.read_exact(&mut buf)) {
            eprintln!("Failed to read window @ 0x{woff:09x}: {err}");
            continue;
        }

        let streams = carve_zlib_streams(&buf, 0);
        let entries = stitch_streams(&streams);
        let mut win_cd = 0usize;
        let mut win_0drp = 0usize;

        for e in &entries {
            let abs_off = woff + (e.offset as u64);
            match e.kind {
                EntryKind::Meta0Drp => win_0drp += 1,
                EntryKind::ClipDictionary if (abs_off & 0xfff) == 0x10 => {
                    let pmap_off = (u64::from_le_bytes(e.data[8..16].try_into().unwrap())
                        & 0x0fff_ffff) as usize;
                    if e.data.len() <= pmap_off {
                        continue; // truncated at window boundary
                    }
                    if let Ok(cd) = CrClipDictionary::parse(&e.data) {
                        win_cd += 1;
                        total_clip_dicts += 1;
                        total_clips += cd.clips.len();
                        total_anims += cd.animations.len();
                        for anim in &cd.animations {
                            total_blocks += anim.blocks.len();
                            for blk in &anim.blocks {
                                total_c10 += blk.class10_verified;
                            }
                            for tf in &anim.track_frames {
                                if let DecodedTrackFrames::Quaternions(qs) = tf {
                                    total_quats += qs.len();
                                    for q in qs {
                                        let nrm =
                                            (q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3])
                                                .sqrt();
                                        let err = (nrm - 1.0).abs();
                                        if err > max_quat_err {
                                            max_quat_err = err;
                                        }
                                    }
                                }
                            }
                        }
                        if !exported {
                            if let Some(out_path) = export_glb_out {
                                for ai in 0..cd.animations.len() {
                                    match cd.export_animation_glb(ai) {
                                        Ok(glb) => {
                                            if let Err(err) = fs::write(out_path, &glb) {
                                                eprintln!("Failed to write GLB to {out_path}: {err}");
                                                std::process::exit(1);
                                            }
                                            println!(
                                                "Exported '{}' ({} B glTF 2.0 .glb) to {out_path}",
                                                cd.animations[ai].name,
                                                glb.len()
                                            );
                                            exported = true;
                                            break;
                                        }
                                        Err(err) => {
                                            eprintln!(
                                                "Skipping animation '{}' export: {err}",
                                                cd.animations[ai].name
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        println!(
            "  Window @ 0x{woff:09x}: {} streams -> {} entries (0DRP_meta={win_0drp}, ClipDict={win_cd})",
            streams.len(),
            entries.len()
        );
    }

    println!(
        "Decoded {total_clip_dicts} ClipDictionaries | {total_clips} clips | {total_anims} animations | {total_blocks} sequence blocks"
    );
    println!(
        "Verified {total_c10} Class-10 superblock curves | {total_quats} unit quaternions (max ||q|-1| = {max_quat_err:.2e})"
    );
    if let Some(out_path) = export_glb_out {
        if !exported {
            eprintln!("Warning: no exportable animations found; did not write {out_path}");
            std::process::exit(1);
        }
    }
}

fn require_flag_value<'a>(args: &'a [String], i: usize, flag: &str) -> &'a str {
    match args.get(i + 1) {
        Some(v) => v.as_str(),
        None => {
            eprintln!("Missing value for {flag}");
            std::process::exit(1);
        }
    }
}

fn parse_usize_flag(args: &[String], i: usize, flag: &str) -> usize {
    let raw = require_flag_value(args, i, flag);
    match raw.parse::<usize>() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Invalid integer for {flag}: {raw}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage:\n  {} inspect-script <script.rpf> [--dump-xml <idx>] [--dump-objgraph <root_idx>]\n  {} inspect-anim <anim.rpf|clipdict.bin> [--export-glb <out.glb>]",
            args[0], args[0]
        );
        std::process::exit(1);
    }
    match args[1].as_str() {
        "inspect-script" => {
            let path = &args[2];
            let mut dump_xml = None;
            let mut dump_og = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--dump-xml" => {
                        dump_xml = Some(parse_usize_flag(&args, i, "--dump-xml"));
                        i += 2;
                    }
                    "--dump-objgraph" => {
                        dump_og = Some(parse_usize_flag(&args, i, "--dump-objgraph"));
                        i += 2;
                    }
                    other => {
                        eprintln!("Unknown flag for inspect-script: {other}");
                        std::process::exit(1);
                    }
                }
            }
            cmd_inspect_script(path, dump_xml, dump_og);
        }
        "inspect-anim" => {
            let path = &args[2];
            let mut export_glb = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--export-glb" => {
                        export_glb = Some(require_flag_value(&args, i, "--export-glb"));
                        i += 2;
                    }
                    other => {
                        eprintln!("Unknown flag for inspect-anim: {other}");
                        std::process::exit(1);
                    }
                }
            }
            cmd_inspect_anim(path, export_glb);
        }
        other => {
            eprintln!("Unknown command: {other}");
            std::process::exit(1);
        }
    }
}
