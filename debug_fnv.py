"""Compare FNV hashing between Python and Rust, and ZIP entry order."""
import os, sys
import zipfile
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from train_model import DENSE_DIM, MAX_TOKENS, extract_features, fnv1a, token, harvest_strings, insert_string

apk_path = r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk"

# Test FNVa hashing
print("=== FNV-1a Test ===")
test_vals = [
    b"name:classes.dex",
    b"name:META-INF/MANIFEST.MF",
    b"manifest:android",
    b"dex:const_string",
    b"perm:INTERNET",
]
for tv in test_vals:
    print(f"  fnv1a({tv!r}) = {fnv1a(tv)}")
    h = fnv1a(tv)
    print(f"    bucket = {h % DENSE_DIM}")

# Check ZIP entry order
print("\n=== ZIP entry order (first 20) ===")
with zipfile.ZipFile(apk_path, 'r') as z:
    for i, name in enumerate(z.namelist()[:20]):
        print(f"  [{i}] {name}")

# Compare extract_features
print("\n=== extract_features (from train_model) ===")
feats = extract_features(apk_path)
if feats is not None:
    print(f"  length: {len(feats)}")
    print(f"  dense[0..20]: {' '.join(f'{x:.4f}' for x in feats[:20])}")
    print(f"  min={feats.min():.4f} max={feats.max():.4f} mean={feats.mean():.4f}")

# Force re-extract to check determinism
print("\n=== Second extraction ===")
feats2 = extract_features(apk_path)
if feats2 is not None:
    same = np.allclose(feats, feats2)
    print(f"  Same as first: {same}")
    if not same:
        print(f"  diff sum: {np.sum(np.abs(feats - feats2))}")
