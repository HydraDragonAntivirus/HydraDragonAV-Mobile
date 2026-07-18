use std::io::Cursor;
use tract_onnx::prelude::*;

fn main() {
    let apk_paths = [
        r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk",
        r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\a2dp.Vol_169.apk",
    ];

    // Load the ONNX model
    let model_bytes = match std::fs::read("model.onnx") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read model.onnx: {e}");
            return;
        }
    };

    let tract_model = match onnx()
        .model_for_read(&mut Cursor::new(&model_bytes))
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: model_for_read: {e}");
            return;
        }
    };

    let tract_model = match tract_model
        .with_input_fact(0, InferenceFact::dt_shape(f32::datum_type(), tvec!(1, hydradragonml::features::DENSE_DIM)))
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: with_input_fact: {e}");
            return;
        }
    };

    let tract_model = match tract_model.into_optimized() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: into_optimized: {e}");
            return;
        }
    };

    let plan = match tract_model.into_runnable() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: into_runnable: {e}");
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
        match hydradragonml::features::extract(&bytes) {
            Some(feats) => {
                println!("  tokens.len() = {}", feats.tokens.len());
                print!("  dense[0..10]: ");
                for v in feats.dense.iter().take(10) {
                    print!("{:.4} ", v);
                }
                println!();
                let norm: f32 = feats.dense.iter().map(|x| x * x).sum::<f32>().sqrt();
                println!("  L2 norm: {:.6}", norm);

                // Run model
                let input = tract_ndarray::Array2::from_shape_vec(
                    (1, hydradragonml::features::DENSE_DIM),
                    feats.dense.clone(),
                )
                .unwrap();
                match plan.run(tvec!(input.into_tensor().into())) {
                    Ok(outputs) => {
                        let output = outputs[0].to_array_view::<f32>().ok();
                        match output {
                            Some(arr) => {
                                let val = arr.iter().copied().next().unwrap_or(0.0);
                                println!("  confidence: {:.6}", val);
                                // Show all output values if multiple
                                println!("  output shape: {:?}", arr.shape());
                                println!("  all values: {:?}", arr.iter().copied().collect::<Vec<f32>>());
                            }
                            None => {
                                println!("  ERROR: to_array_view failed");
                            }
                        }
                    }
                    Err(e) => {
                        println!("  ERROR: plan.run: {e}");
                    }
                }
            }
            None => {
                eprintln!("  ERROR: extract returned None");
            }
        }
    }
}
