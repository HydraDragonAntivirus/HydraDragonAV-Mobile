import sys
import json
import onnxruntime as ort

# train_model.py aynı klasordeyse dogrudan import edebiliriz
from train_model import extract_features

def main():
    if len(sys.argv) < 2:
        print("Kullanim: python a123imp.py <apk_yolu> [<apk_yolu2> ...]")
        sys.exit(1)

    sess = ort.InferenceSession("model.onnx")
    input_name = sess.get_inputs()[0].name

    for apk_path in sys.argv[1:]:
        feats = extract_features(apk_path)
        if feats is None:
            print(f"{apk_path}: ERROR - feature cikarilamadi (zip acilamadi / token yok)")
            continue

        feats_2d = feats.reshape(1, -1)  # (1, 256)
        out = sess.run(None, {input_name: feats_2d})
        confidence = float(out[0].flat[0])
        print(f"{apk_path}: confidence={confidence:.6f}  ->  {'MALWARE' if confidence >= 0.5 else 'BENIGN'}")

        # debug: dense vektoru dosyaya yaz, Rust ciktisiyla karsilastirmak icin
        dump_path = apk_path + ".python_dense.json"
        with open(dump_path, "w") as f:
            json.dump([float(x) for x in feats], f)
        print(f"  -> dense vektor yazildi: {dump_path}")


if __name__ == "__main__":
    main()
