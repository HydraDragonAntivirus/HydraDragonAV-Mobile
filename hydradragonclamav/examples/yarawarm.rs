use std::time::Instant;

use hydradragonclamav::Engine;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: yarawarm <scan_assets_dir>");
        std::process::exit(2);
    }
    let base = std::path::Path::new(&args[1]);
    let mut c = match Engine::from_database_dir(base) {
        Ok((e, _)) => e,
        Err(e) => {
            eprintln!("clamav DB load failed: {e}");
            std::process::exit(1);
        }
    };
    for name in [
        "clean_rules_filtered_verified.yrc",
        "valhalla-rules_filtered_verified.yrc",
        "machine_learning_apk.yrc",
        "androguard.yrc",
        "hips_rules_filtered_verified.yrc",
    ] {
        let t0 = Instant::now();
        let p = base.join(name);
        let added = if p.exists() {
            c.add_compiled_yara_file(&p).is_some()
        } else {
            false
        };
        println!("load {name}: {}ms added={added}", t0.elapsed().as_millis());
    }

    let data = b"hello world this is a scan test buffer".to_vec();
    let opts = hydradragonclamav::ScanOptions::default();
    let names: Vec<String> = c.yara.iter().map(|y| y.name.clone()).collect();
    for name in &names {
        let t0 = Instant::now();
        let r = c.scan_bytes_named(&data, "test", opts, &[]);
        println!("first-scan {}: {}ms ({} matches)", name, t0.elapsed().as_millis(), r.len());
    }
    for name in &names {
        let t0 = Instant::now();
        let r = c.scan_bytes_named(&data, "test", opts, &[]);
        println!("warm-scan {}: {}ms ({} matches)", name, t0.elapsed().as_millis(), r.len());
    }
}
