import os
import re
import zipfile

import numpy as np
import onnx
from onnx import helper, TensorProto, numpy_helper
import torch
import torch.nn as nn

DENSE_DIM = 2048
MIN_STR_LEN = 5
MAX_TOKENS = 120000
MAX_ENTRY_SCAN = 16 * 1024 * 1024

# FNV-1a 64-bit constants (must match Rust exactly)
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x00000100000001b3


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def token(prefix: str, s: bytes) -> int:
    return fnv1a(prefix.encode() + s)


# ---------------------------------------------------------------------------
# Precompute the FNV-1a state AFTER hashing each prefix string.
# token(prefix, s) == _continue_fnv1a(_PREFIX_STATE[prefix], s)
# This is valid because FNV-1a is purely sequential state-based.
# ---------------------------------------------------------------------------
def _fnv1a_state(prefix_bytes: bytes) -> int:
    h = FNV_OFFSET
    for b in prefix_bytes:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


_PREFIX_STATE: dict = {}
for _p in ('name:', 'dex:', 'manifest:', 'res:', 'perm:', 'api:', 'url:'):
    _PREFIX_STATE[_p] = _fnv1a_state(_p.encode())


def _token_fast(prefix: str, s: bytes) -> int:
    """Like token() but skips re-hashing the prefix on every call."""
    h = _PREFIX_STATE[prefix]
    for b in s:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# Compiled regexes — scanning runs in C, avoiding Python byte-by-byte loops
# ---------------------------------------------------------------------------
_ASCII_RE = re.compile(b'[\x20-\x7e]{%d,}' % MIN_STR_LEN)
_UTF16_RE = re.compile(b'(?:[\x20-\x7e]\x00){%d,}' % MIN_STR_LEN)

# Valid permission name chars (integers, as returned by bytes indexing)
_PERM_CHARS = frozenset(
    list(range(ord('a'), ord('z') + 1)) +
    list(range(ord('A'), ord('Z') + 1)) +
    list(range(ord('0'), ord('9') + 1)) +
    [ord('_')]
)
_PERM_PAT = b'permission.'


def harvest_strings(data: bytes, prefix: str, tokens: set):
    """Extract printable ASCII and UTF-16LE runs using compiled C-level regexes."""
    # ASCII runs
    for m in _ASCII_RE.finditer(data):
        insert_string(m.group(0), prefix, tokens)
        if len(tokens) >= MAX_TOKENS:
            return
    # UTF-16LE runs: every other byte (the high byte is 0x00, discard it)
    for m in _UTF16_RE.finditer(data):
        insert_string(m.group(0)[::2], prefix, tokens)
        if len(tokens) >= MAX_TOKENS:
            return


def insert_string(s: bytes, prefix: str, tokens: set):
    """Insert a printable-run token and promote high-signal sub-tokens.

    Works purely on bytes to avoid str decode overhead.
    Results are identical to the original string-based version.
    """
    tokens.add(_token_fast(prefix, s))

    ls = s.lower()  # bytes.lower() — C-level, fast

    # Permission token: look for b'permission.' in the lowercased run
    idx = ls.find(_PERM_PAT)
    if idx >= 0:
        after = ls[idx + 11:]
        end = 0
        while end < len(after) and after[end] in _PERM_CHARS:
            end += 1
        if end > 0:
            tokens.add(_token_fast('perm:', after[:end]))

    # API descriptor: starts with 'L' (0x4c) and contains '/' (0x2f)
    if s and s[0] == 0x4c and b'/' in s[1:]:
        tokens.add(_token_fast('api:', s))

    # URL / protocol
    if b'://' in s:
        tokens.add(_token_fast('url:', ls))


def extract_features(apk_path: str):
    try:
        z = zipfile.ZipFile(apk_path, 'r')
        namelist = z.namelist()
    except Exception:
        return None

    tokens = set()
    for name in namelist:
        if len(tokens) >= MAX_TOKENS:
            break
        tokens.add(_token_fast('name:', name.encode()))
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
        harvest_strings(data, prefix, tokens)
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
    return v


def _extract_one(args):
    path, label = args
    feats = extract_features(path)
    if feats is not None:
        return feats, label
    return None


def gather_dataset(dataset_root: str):
    import concurrent.futures
    try:
        from tqdm import tqdm
    except ImportError:
        tqdm = lambda x, **kw: x

    jobs = []
    for root, dirs, files in os.walk(dataset_root):
        for fname in files:
            if not fname.lower().endswith('.apk'):
                continue
            if 'invalid' in root.lower():
                continue
            path = os.path.join(root, fname)
            label = 1 if 'malware' in root.lower() else 0
            jobs.append((path, label))

    X, y = [], []
    n_workers = max(1, os.cpu_count() or 4)
    with concurrent.futures.ProcessPoolExecutor(max_workers=n_workers) as pool:
        for result in tqdm(pool.map(_extract_one, jobs), total=len(jobs), desc='Extracting'):
            if result is not None:
                feats, label = result
                X.append(feats)
                y.append(label)
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


class Net(nn.Module):
    """3-layer MLP with dropout.  Input: DENSE_DIM=2048 features."""
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(DENSE_DIM, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x).squeeze(-1)


def main():
    import sys
    dataset = sys.argv[1] if len(sys.argv) > 1 else 'dataset'
    print(f'Scanning {dataset}...')
    X, y = gather_dataset(dataset)
    print(f'\nLoaded {len(X)} samples ({y.sum()} malware, {len(y) - y.sum()} benign)')

    if len(X) == 0:
        print('ERROR: no APKs found')
        return

    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    split = int(len(X) * 0.8)
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    pos_weight = float((len(y_train) - y_train.sum()) / max(y_train.sum(), 1))
    model = Net()
    criterion     = nn.BCELoss(reduction='none')
    val_criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)

    X_t = torch.from_numpy(X_train)
    y_t = torch.from_numpy(y_train).float()
    X_v = torch.from_numpy(X_val)
    y_v = torch.from_numpy(y_val).float()
    pos_w = torch.tensor(pos_weight)

    best_val_loss = float('inf')
    stall = 0
    for epoch in range(300):
        model.train()
        optimizer.zero_grad()
        outputs = model(X_t)
        per_sample = criterion(outputs, y_t)
        weight_vec = torch.where(y_t == 1, pos_w, torch.ones(1))
        loss = (per_sample * weight_vec).mean()
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            preds   = (outputs > 0.5).float()
            v_out   = model(X_v)
            v_loss  = val_criterion(v_out, y_v).item()
            v_preds = (v_out > 0.5).float()
            v_tp    = (v_preds * y_v).sum().item()
            v_fn    = ((1 - v_preds) * y_v).sum().item()
            v_fp    = (v_preds * (1 - y_v)).sum().item()
            v_f1    = 2 * v_tp / (2 * v_tp + v_fn + v_fp + 1e-8)
            v_acc   = (v_preds == y_v).float().mean().item()
        scheduler.step(v_loss)
        print(f'  Epoch {epoch+1:3d} loss={loss.item():.4f} val_loss={v_loss:.4f} '
              f'val_acc={v_acc:.4f} val_f1={v_f1:.4f}')
        if v_loss < best_val_loss:
            best_val_loss = v_loss
            stall = 0
        else:
            stall += 1
            if stall >= 25:
                print(f'  Early stop at epoch {epoch+1}, best val_loss={best_val_loss:.4f}')
                break

    # Export to ONNX using torch.onnx.export (requires onnxscript)
    model.eval()
    dummy = torch.zeros(1, DENSE_DIM)
    torch.onnx.export(
        model,
        dummy,
        'model.onnx',
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={'input': {0: 'batch'}, 'output': {0: 'batch'}},
        opset_version=11,
    )
    print('\nOK model.onnx exported (opset 11)')


if __name__ == '__main__':
    main()
