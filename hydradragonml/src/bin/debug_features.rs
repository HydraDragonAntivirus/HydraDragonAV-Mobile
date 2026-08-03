use std::path::PathBuf;

use hydradragonml::features::{EngineFeatures, Tokenizer};
use hydradragonml::Model;

struct Args {
    apk: PathBuf,
    model: PathBuf,
    vocab: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut apk = None;
        let mut model = None;
        let mut vocab = None;

        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let mut val = || it.next().ok_or_else(|| format!("missing value for {arg}"));
            match arg.as_str() {
                "--apk" => apk = Some(PathBuf::from(val()?)),
                "--model" => model = Some(PathBuf::from(val()?)),
                "--vocab" => vocab = Some(PathBuf::from(val()?)),
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        Ok(Self {
            apk: apk.ok_or("missing --apk <file.apk>")?,
            model: model.ok_or("missing --model <model.mpk>")?,
            vocab: vocab.ok_or("missing --vocab <vocab.json>")?,
        })
    }
}

fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            eprintln!("Usage: debug-features --apk <file.apk> --model <model.mpk> --vocab <vocab.json>");
            std::process::exit(2);
        }
    };

    let apk = read_or_exit(&args.apk, "APK");
    let model_bytes = read_or_exit(&args.model, "model");
    let vocab_bytes = read_or_exit(&args.vocab, "vocab");

    let tokenizer = Tokenizer::load_json(&vocab_bytes).unwrap_or_else(|| {
        eprintln!("ERROR: failed to parse vocab '{}'", args.vocab.display());
        std::process::exit(2);
    });
    let token_ids = tokenizer.tokenize(&apk).unwrap_or_default();
    let non_zero_tokens = token_ids.iter().filter(|&&id| id != 0).count();

    let device = burn::backend::ndarray::NdArrayDevice::default();
    let model = Model::load(&model_bytes, &vocab_bytes, device).unwrap_or_else(|err| {
        eprintln!("ERROR: failed to load model: {err}");
        std::process::exit(2);
    });

    let real_features = EngineFeatures::extract_from_apk(&apk).unwrap_or_default();
    let zero_features = EngineFeatures::default();

    println!("apk                 = {}", args.apk.display());
    println!("token_count         = {}", token_ids.len());
    println!("non_zero_tokens     = {}", non_zero_tokens);
    print_score("zero_engine_features", &model, &apk, &zero_features);
    print_score("real_engine_features", &model, &apk, &real_features);

    println!();
    println!("real feature vector = {:?}", real_features.to_vec());
}

fn read_or_exit(path: &PathBuf, label: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| {
        eprintln!("ERROR: failed to read {label} '{}': {err}", path.display());
        std::process::exit(2);
    })
}

fn print_score(label: &str, model: &Model, apk: &[u8], features: &EngineFeatures) {
    match model.scan_with_features(apk, features) {
        Some(result) => {
            println!(
                "{label:<21}= malicious={} suspicious={} confidence={:.9}",
                result.malicious, result.suspicious, result.confidence
            );
        }
        None => println!("{label:<21}= scan failed"),
    }
}
