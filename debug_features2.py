"""Compare Python and Rust feature extraction in detail for one APK."""
import os, sys
import numpy as np
import zipfile

sys.path.insert(0, os.path.dirname(__file__))
from train_model import DENSE_DIM, extract_features, fnv1a, token, harvest_strings, insert_string

apk_path = r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk"

# Step 1: List all entries in the ZIP
with zipfile.ZipFile(apk_path, 'r') as z:
    namelist = z.namelist()
    print(f"Total entries in ZIP: {len(namelist)}")
    print(f"First 10 entries: {namelist[:10]}")
    
    # Check file sizes
    for name in namelist[:5]:
        info = z.getinfo(name)
        print(f"  {name}: size={info.file_size}")

# Step 2: Run extraction and count tokens
tokens = set()
MAX_TOKENS = 120000
MIN_STR_LEN = 5
MAX_ENTRY_SCAN = 16 * 1024 * 1024

with zipfile.ZipFile(apk_path, 'r') as z:
    namelist = z.namelist()
    
    for name in namelist:
        if len(tokens) >= MAX_TOKENS:
            break
        tokens.add(token('name:', name.encode()))
        lname = name.lower()
        scan = (lname == 'androidmanifest.xml' or lname == 'resources.arsc'
                or lname.endswith('.dex') or lname.startswith('meta-inf/'))
        if not scan:
            continue
        
        try:
            info = z.getinfo(name)
            if info.file_size > MAX_ENTRY_SCAN:
                data = z.read(name)[:MAX_ENTRY_SCAN]
            else:
                data = z.read(name)
        except Exception as e:
            print(f"  ERROR reading {name}: {e}")
            continue
        
        if lname.endswith('.dex'):
            prefix = 'dex:'
        elif lname == 'androidmanifest.xml':
            prefix = 'manifest:'
        else:
            prefix = 'res:'
        harvest_strings(data, prefix, tokens)

print(f"\nTotal tokens after Python extraction: {len(tokens)}")

# Step 3: Show token bucket distribution
counts = [0] * DENSE_DIM
for t in tokens:
    bucket = t % DENSE_DIM
    counts[bucket] = min(counts[bucket] + 1, 0xFFFFFFFF)

v = np.array([np.log1p(c) for c in counts], dtype=np.float32)
norm = np.sqrt(np.sum(v * v))
if norm > 0:
    v /= norm

print(f"dense[0..20]: {' '.join(f'{x:.4f}' for x in v[:20])}")
print(f"min={v.min():.4f} max={v.max():.4f} mean={v.mean():.4f} std={v.std():.4f}")

# Show empty buckets
empty = [i for i, c in enumerate(counts) if c == 0]
print(f"Empty buckets: {len(empty)}")
