import hashlib
import os
import struct
import zipfile

import numpy as np
import torch
import torch.nn as nn
import torch.onnx

DENSE_DIM = 256
MIN_STR_LEN = 5
MAX_TOKENS = 120000
MAX_ENTRY_SCAN = 16 * 1024 * 1024

# FNV-1a 64-bit constants
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x00000100000001b3


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def token(prefix: str, s: bytes) -> int:
    return fnv1a(prefix.encode() + s)


def harvest_strings(data: bytes, prefix: str, tokens: set):
    # ASCII runs
    start = None
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f:
            if start is None:
                start = i
        elif start is not None:
            if i - start >= MIN_STR_LEN:
                insert_string(data[start:i], prefix, tokens)
                if len(tokens) >= MAX_TOKENS:
                    return
            start = None
    if start is not None and len(data) - start >= MIN_STR_LEN:
        insert_string(data[start:], prefix, tokens)

    # UTF-16LE runs
    buf = bytearray()
    j = 0
    while j + 1 < len(data):
        lo = data[j]
        hi = data[j + 1]
        if hi == 0 and 0x20 <= lo < 0x7f:
            buf.append(lo)
        else:
            if len(buf) >= MIN_STR_LEN:
                insert_string(bytes(buf), prefix, tokens)
                if len(tokens) >= MAX_TOKENS:
                    return
            buf.clear()
        j += 2
    if len(buf) >= MIN_STR_LEN:
        insert_string(bytes(buf), prefix, tokens)


def insert_string(s: bytes, prefix: str, tokens: set):
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


def extract_features(apk_path: str):
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
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
            info = z.getinfo(name)
            if info.file_size > MAX_ENTRY_SCAN:
                data = z.read(name)[:MAX_ENTRY_SCAN]
            else:
                data = z.read(name)
        except Exception:
            continue
        if lname.endswith('.dex'):
            prefix = 'dex:'
        elif lname == 'androidmanifest.xml':
            prefix = 'manifest:'
        else:
            prefix = 'res:'
        harvest_strings(data, prefix, tokens)

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
    return v


def gather_dataset(dataset_root: str):
    X, y = [], []
    for root, dirs, files in os.walk(dataset_root):
        for fname in files:
            if not fname.lower().endswith('.apk'):
                continue
            if 'invalid' in root.lower():
                continue
            path = os.path.join(root, fname)
            label = 1 if 'malware' in root.lower() else 0
            feats = extract_features(path)
            if feats is not None:
                X.append(feats)
                y.append(label)
                print(f"  {'MALWARE' if label else 'BENIGN'} {fname}")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


class Net(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(DENSE_DIM, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x).squeeze(-1)


def main():
    import sys
    dataset = sys.argv[1] if len(sys.argv) > 1 else "dataset"
    print(f"Scanning {dataset}...")
    X, y = gather_dataset(dataset)
    print(f"\nLoaded {len(X)} samples ({y.sum()} malware, {len(y) - y.sum()} benign)")

    if len(X) == 0:
        print("ERROR: no APKs found")
        return

    model = Net()
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    X_t = torch.from_numpy(X)
    y_t = torch.from_numpy(y).float()

    model.train()
    for epoch in range(20):
        optimizer.zero_grad()
        outputs = model(X_t)
        loss = criterion(outputs, y_t)
        loss.backward()
        optimizer.step()
        preds = (outputs > 0.5).float()
        acc = (preds == y_t).float().mean().item()
        print(f"  Epoch {epoch+1:2d} loss={loss.item():.4f} acc={acc:.4f}")

    model.eval()
    dummy = torch.randn(1, DENSE_DIM)
    torch.onnx.export(
        model,
        dummy,
        "model.onnx",
        input_names=["input"],
        output_names=["output"],
        opset_version=9,
        dynamic_axes={"input": {0: "batch"}, "output": {0: "batch"}},
    )
    print("\nOK model.onnx exported")


if __name__ == "__main__":
    main()
