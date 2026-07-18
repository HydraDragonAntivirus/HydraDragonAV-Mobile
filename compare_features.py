"""Compare old vs new feature extraction."""
import sys, zipfile
import numpy as np

sys.path.insert(0, '.')

# === OLD code behavior (from_utf8 + to_ascii_lowercase, two-pass) ===
DENSE_DIM = 256
MIN_STR_LEN = 5
MAX_TOKENS = 120000
MAX_ENTRY_SCAN = 16 * 1024 * 1024

FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x00000100000001b3

def fnv1a(data):
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def token(prefix, s):
    return fnv1a(prefix.encode() + s)

def insert_string_old(s, prefix, tokens):
    tokens.add(token(prefix, s))
    try:
        text = s.decode('utf-8', errors='replace')
        lower = text.lower()
        if 'permission.' in lower:
            parts = lower.split('permission.', 1)
            if len(parts) > 1:
                perm = ''.join(c for c in parts[1] if c.isalnum() or c == '_')
                if perm:
                    tokens.add(token('perm:', perm.encode()))
        if text.startswith('L') and '/' in text:
            tokens.add(token('api:', text.encode()))
        if lower.startswith('http://') or lower.startswith('https://') or '://' in lower:
            tokens.add(token('url:', lower.encode()))
    except Exception:
        pass

def harvest_strings_old(data, prefix, tokens):
    start = None
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if start is None:
                start = i
        elif start is not None:
            if i - start >= MIN_STR_LEN:
                insert_string_old(data[start:i], prefix, tokens)
                if len(tokens) >= MAX_TOKENS:
                    return
            start = None
    if start is not None and len(data) - start >= MIN_STR_LEN:
        insert_string_old(data[start:], prefix, tokens)
    buf = bytearray()
    j = 0
    while j + 1 < len(data):
        lo = data[j]
        hi = data[j + 1]
        if hi == 0 and 0x20 <= lo < 0x7f:
            buf.append(lo)
        else:
            if len(buf) >= MIN_STR_LEN:
                insert_string_old(bytes(buf), prefix, tokens)
                if len(tokens) >= MAX_TOKENS:
                    return
            buf.clear()
        j += 2
    if len(buf) >= MIN_STR_LEN:
        insert_string_old(bytes(buf), prefix, tokens)

def extract_old(apk_path):
    try:
        z = zipfile.ZipFile(apk_path, 'r')
        namelist = z.namelist()
    except Exception:
        return None
    tokens = set()
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
            with z.open(name) as f:
                data = f.read(MAX_ENTRY_SCAN) or b''
        except Exception:
            continue
        if lname.endswith('.dex'):
            prefix = 'dex:'
        elif lname == 'androidmanifest.xml':
            prefix = 'manifest:'
        else:
            prefix = 'res:'
        harvest_strings_old(data, prefix, tokens)
    z.close()
    if not tokens:
        return None
    counts = [0] * DENSE_DIM
    for t in tokens:
        bucket = t % DENSE_DIM
        counts[bucket] = min(counts[bucket] + 1, 0xFFFFFFFF)
    v = np.array([np.log1p(c) for c in counts], dtype=np.float32)
    norm = np.sqrt(np.sum(v * v))
    if norm > 0:
        v /= norm
    return v, len(tokens)

# === NEW code (current train_model.py) ===
from train_model import extract_features as extract_new

apk = r'dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk'

feats_old, n_old = extract_old(apk)
feats_new = extract_new(apk)

print(f'Old tokens: {n_old}')
print(f'New tokens: {len(set(feats_new.round(6)))} (dense dim)')

if feats_old is not None and feats_new is not None:
    match = np.allclose(feats_old, feats_new, atol=1e-6)
    max_diff = np.max(np.abs(feats_old - feats_new))
    print(f'Match: {match}')
    print(f'Max diff: {max_diff:.10f}')
    if not match:
        print(f'Old[:10]: {feats_old[:10].round(6)}')
        print(f'New[:10]: {feats_new[:10].round(6)}')
    
    import onnxruntime as ort
    sess = ort.InferenceSession('model.onnx')
    input_name = sess.get_inputs()[0].name
    out_old = sess.run(['output'], {input_name: feats_old.reshape(1,-1).astype(np.float32)})[0]
    out_new = sess.run(['output'], {input_name: feats_new.reshape(1,-1).astype(np.float32)})[0]
    print(f'Old onnx: {out_old[0,0]:.6f}')
    print(f'New onnx: {out_new[0,0]:.6f}')
