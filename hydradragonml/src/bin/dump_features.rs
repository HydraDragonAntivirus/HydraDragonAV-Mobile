use hydradragonml::features::EngineFeatures;
use std::io::Read;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: dump-apk-features <apk>");
        std::process::exit(1);
    });
    let bytes = std::fs::read(&path).expect("read apk");

    let reader = std::io::Cursor::new(&bytes);
    if let Ok(mut archive) = zip::ZipArchive::new(reader) {
        for i in 0..archive.len() {
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let lname = entry.name().to_ascii_lowercase();
            if lname == "androidmanifest.xml" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf).ok();
                println!("manifest entry {:?} bytes", buf.len());
                let mut off = 0usize;
                if u16::from_le_bytes([buf[0], buf[1]]) == 0x0003 {
                    let hs = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                    off = hs;
                }
                let mut pool_strings: Vec<String> = Vec::new();
                let mut resmap: Vec<u32> = Vec::new();
                while off + 8 <= buf.len() {
                    let ct = u16::from_le_bytes([buf[off], buf[off + 1]]);
                    let hs = u16::from_le_bytes([buf[off + 2], buf[off + 3]]) as usize;
                    let cs = u32::from_le_bytes([
                        buf[off + 4],
                        buf[off + 5],
                        buf[off + 6],
                        buf[off + 7],
                    ]) as usize;
                    if ct == 0x0001 {
                        let sc = u32::from_le_bytes([
                            buf[off + 8],
                            buf[off + 9],
                            buf[off + 10],
                            buf[off + 11],
                        ]) as usize;
                        let is_utf8 = u32::from_le_bytes([
                            buf[off + 16],
                            buf[off + 17],
                            buf[off + 18],
                            buf[off + 19],
                        ]) & 0x100
                            != 0;
                        let ss = u32::from_le_bytes([
                            buf[off + 20],
                            buf[off + 21],
                            buf[off + 22],
                            buf[off + 23],
                        ]) as usize;
                        for i in 0..sc {
                            let eo = off + hs + i * 4;
                            let so = off
                                + ss
                                + u32::from_le_bytes([
                                    buf[eo],
                                    buf[eo + 1],
                                    buf[eo + 2],
                                    buf[eo + 3],
                                ]) as usize;
                            let s = if is_utf8 {
                                let mut p = so + 2;
                                let b0 = buf[p];
                                if b0 & 0x80 != 0 {
                                    p += 1;
                                }
                                p += 1;
                                let len = buf[p];
                                let start = p + 1;
                                String::from_utf8_lossy(&buf[start..start + len as usize])
                                    .into_owned()
                            } else {
                                let len = u16::from_le_bytes([buf[so], buf[so + 1]]) as usize;
                                let units: Vec<u16> = (0..len)
                                    .map(|j| {
                                        u16::from_le_bytes([
                                            buf[so + 2 + j * 2],
                                            buf[so + 3 + j * 2],
                                        ])
                                    })
                                    .collect();
                                String::from_utf16_lossy(&units)
                            };
                            pool_strings.push(s);
                        }
                    } else if ct == 0x0180 {
                        let mut p = off + hs;
                        while p + 4 <= off + cs {
                            resmap.push(u32::from_le_bytes([
                                buf[p],
                                buf[p + 1],
                                buf[p + 2],
                                buf[p + 3],
                            ]));
                            p += 4;
                        }
                    } else if ct == 0x0102 {
                        let node_off = off + 8;
                        let name_idx = i32::from_le_bytes([
                            buf[node_off + 8 + 4],
                            buf[node_off + 8 + 5],
                            buf[node_off + 8 + 6],
                            buf[node_off + 8 + 7],
                        ]);
                        let elem = pool_strings
                            .get(name_idx as usize)
                            .cloned()
                            .unwrap_or_default();
                        if elem.contains("permission") && !elem.contains("Permission") {
                            let aoff = u16::from_le_bytes([buf[node_off + 16], buf[node_off + 17]])
                                as usize;
                            let asize = u16::from_le_bytes([buf[node_off + 18], buf[node_off + 19]])
                                as usize;
                            let acount =
                                u16::from_le_bytes([buf[node_off + 20], buf[node_off + 21]])
                                    as usize;
                            let abase = node_off + aoff;
                            for i in 0..acount {
                                let ao = abase + i * asize;
                                let name_idx = i32::from_le_bytes([
                                    buf[ao + 4],
                                    buf[ao + 5],
                                    buf[ao + 6],
                                    buf[ao + 7],
                                ]);
                                let raw_idx = i32::from_le_bytes([
                                    buf[ao + 8],
                                    buf[ao + 9],
                                    buf[ao + 10],
                                    buf[ao + 11],
                                ]);
                                let res =
                                    resmap.get(name_idx.max(0) as usize).copied().unwrap_or(0);
                                let val = pool_strings
                                    .get(raw_idx.max(0) as usize)
                                    .cloned()
                                    .unwrap_or_default();
                                println!("     elem={elem} attr_id=0x{res:08x} value={val}");
                            }
                        }
                    }
                    off += cs;
                }
                println!(
                    "resmap={} samples={:?} pool={}",
                    resmap.len(),
                    &resmap[..resmap.len().min(6)],
                    pool_strings.len()
                );
                match hydradragonml::features::axml::analyze_manifest(&buf) {
                    Some(m) => {
                        println!(
                            "  dangerous={} total={} act={} svc={} recv={} min_sdk={} target_sdk={}",
                            m.dangerous_permissions,
                            m.total_permissions,
                            m.activities,
                            m.services,
                            m.receivers,
                            m.min_sdk,
                            m.target_sdk
                        );
                    }
                    None => println!("  analyze_manifest returned None"),
                }
            }
        }
    }
    let t0 = std::time::Instant::now();
    match EngineFeatures::extract_from_apk(&bytes) {
        Some(f) => {
            println!("extract ok in {:.3}s", t0.elapsed().as_secs_f64());
            println!("dex_class_count          = {:.0}", f.dex_class_count);
            println!("dex_string_count         = {:.0}", f.dex_string_count);
            println!("dex_api_call_count       = {:.0}", f.dex_api_call_count);
            println!("dex_finding_high         = {:.0}", f.dex_finding_high);
            println!("dex_finding_critical     = {:.0}", f.dex_finding_critical);
            println!("elf_count                = {:.0}", f.elf_count);
            println!("elf_emulated_strings     = {:.0}", f.elf_emulated_strings);
            println!("elf_network_calls        = {:.0}", f.elf_network_calls);
            println!("elf_file_calls           = {:.0}", f.elf_file_calls);
            println!("elf_exec_calls           = {:.0}", f.elf_exec_calls);
            println!("elf_anti_debug           = {:.0}", f.elf_anti_debug);
            println!(
                "manifest_dang_perms      = {:.0}",
                f.manifest_dangerous_permissions
            );
            println!(
                "manifest_total_perms     = {:.0}",
                f.manifest_total_permissions
            );
            println!("manifest_activities      = {:.0}", f.manifest_activities);
            println!("manifest_services        = {:.0}", f.manifest_services);
            println!("manifest_receivers       = {:.0}", f.manifest_receivers);
            println!("manifest_min_sdk         = {:.0}", f.manifest_min_sdk);
            println!("manifest_target_sdk      = {:.0}", f.manifest_target_sdk);
            println!("normalized              = {:?}", f.to_vec());
        }
        None => println!("extract returned None (no relevant entries found)"),
    }
}
