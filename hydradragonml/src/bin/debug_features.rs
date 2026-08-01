fn main() {
    let apk_paths = [
        r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk",
        r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\a2dp.Vol_169.apk",
    ];

    let model_bytes = match std::fs::read("model.mpk") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read model.mpk: {e}");
            return;
        }
    };
    let vocab_bytes = match std::fs::read("vocab.json") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read vocab.json: {e}");
            return;
        }
    };

    let device = burn::backend::cpu::CpuDevice::default();
    let model = match hydradragonml::Model::load(&model_bytes, &vocab_bytes, device) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: Model::load: {e}");
            return;
        }
    };

    for apk_path in &apk_paths {
        let path = std::path::Path::new(apk_path);
        if !path.exists() {
            eprintln!("SKIP: {} does not exist", apk_path);
            continue;
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("ERROR reading {}: {}", apk_path, e);
                continue;
            }
        };

        println!("=== {} ===", path.file_name().unwrap().to_string_lossy());
        match model.scan(&bytes) {
            Some(result) => {
                println!("  malicious: {}", result.malicious);
                println!("  suspicious: {}", result.suspicious);
                println!("  confidence: {:.6}", result.confidence);
            }
            None => {
                eprintln!("  ERROR: scan returned None");
            }
        }
    }
}
