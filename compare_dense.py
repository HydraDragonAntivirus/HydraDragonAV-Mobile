import json
import sys

def main():
    if len(sys.argv) != 3:
        print("Kullanim: python compare_dense.py <x.python_dense.json> <x.rust_dense.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        py = json.load(f)
    with open(sys.argv[2]) as f:
        rs = json.load(f)

    if len(py) != len(rs):
        print(f"UZUNLUK FARKLI: python={len(py)} rust={len(rs)}")
        return

    diffs = []
    for i, (a, b) in enumerate(zip(py, rs)):
        if abs(a - b) > 1e-4:
            diffs.append((i, a, b))

    if not diffs:
        print("AYNI: iki vektor birbirine ozdes (tolerans 1e-4).")
        print("-> Sorun feature extraction'da degil, baska bir yerde.")
    else:
        print(f"FARKLI: {len(diffs)}/{len(py)} bucket uyusmuyor:")
        for i, a, b in diffs[:20]:
            print(f"  bucket[{i}]: python={a:.6f}  rust={b:.6f}")
        if len(diffs) > 20:
            print(f"  ... ve {len(diffs)-20} tane daha")
        print("-> Sorun feature extraction'da: iki taraf farkli token/string cikariyor.")

if __name__ == "__main__":
    main()
