// src/bin/dump_features.rs olarak projene ekle
// Cagirma: cargo run --bin dump_features -- <apk_yolu>
//
// Ciktisi: <apk_yolu>.rust_dense.json  -> Python'un urettigi
// <apk_yolu>.python_dense.json ile birebir karsilastir.

use std::env;
use std::fs;

use hydradragonml::features;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Kullanim: dump_features <apk_yolu>");
        std::process::exit(1);
    }
    let apk_path = &args[1];
    let bytes = fs::read(apk_path).expect("apk okunamadi");

    let feats = match features::extract(&bytes) {
        Some(f) => f,
        None => {
            eprintln!("ERROR: features::extract None dondu (zip acilamadi / token yok)");
            std::process::exit(1);
        }
    };

    println!("token_count={}", feats.tokens.len());
    println!("dense={:?}", feats.dense);

    let parts: Vec<String> = feats.dense.iter().map(|x| x.to_string()).collect();
    let json = format!("[{}]", parts.join(","));
    let out_path = format!("{}.rust_dense.json", apk_path);
    fs::write(&out_path, json).expect("yazilamadi");
    println!("-> dense vektor yazildi: {}", out_path);
}
