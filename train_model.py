import os
import zipfile

import numpy as np
import onnx
from onnx import helper, TensorProto, numpy_helper
import torch
import torch.nn as nn

DENSE_DIM = 256
MIN_STR_LEN = 5
MAX_TOKENS = 120000
MAX_ENTRY_SCAN = 16 * 1024 * 1024

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
    ascii_start = None
    utf16_buf = bytearray()
    n = len(data)

    for i in range(n):
        b = data[i]
        printable = 0x20 <= b < 0x7f

        if printable:
            if ascii_start is None:
                ascii_start = i
        elif ascii_start is not None:
            if i - ascii_start >= MIN_STR_LEN:
                insert_string(data[ascii_start:i], prefix, tokens)
                if len(tokens) >= MAX_TOKENS:
                    return
            ascii_start = None

        if i & 1 == 0 and i + 1 < n:
            hi = data[i + 1]
            if hi == 0 and printable:
                utf16_buf.append(b)
            elif len(utf16_buf) >= MIN_STR_LEN:
                insert_string(bytes(utf16_buf), prefix, tokens)
                if len(tokens) >= MAX_TOKENS:
                    return
                utf16_buf.clear()
            else:
                utf16_buf.clear()

    if ascii_start is not None and n - ascii_start >= MIN_STR_LEN:
        insert_string(data[ascii_start:], prefix, tokens)
    if len(utf16_buf) >= MIN_STR_LEN:
        insert_string(bytes(utf16_buf), prefix, tokens)


def insert_string(s: bytes, prefix: str, tokens: set):
    tokens.add(token(prefix, s))

    try:
        if len(s) >= 11:
            idx = s.lower().find(b'permission.')
            if idx >= 0:
                after = s[idx + 11:]
                end = 0
                while end < len(after):
                    c = after[end]
                    if not (c.isalnum() or c == 95):  # 95 = ord('_')
                        break
                    end += 1
                if end > 0:
                    tokens.add(token('perm:', after[:end].lower()))

        if len(s) > 1 and s[0] == 76 and 47 in s[1:]:  # ord('L')=76, ord('/')=47
            tokens.add(token('api:', s))

        if b'://' in s:
            tokens.add(token('url:', s))
    except Exception:
        pass


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
        for result in tqdm(pool.map(_extract_one, jobs), total=len(jobs), desc="Extracting"):
            if result is not None:
                feats, label = result
                X.append(feats)
                y.append(label)
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

    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    split = int(len(X) * 0.8)
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    pos_weight = (len(y_train) - y_train.sum()) / y_train.sum()
    model = Net()
    criterion = nn.BCELoss(reduction='none')
    val_criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    X_t = torch.from_numpy(X_train)
    y_t = torch.from_numpy(y_train).float()
    X_v = torch.from_numpy(X_val)
    y_v = torch.from_numpy(y_val).float()
    pos_weight_tensor = torch.tensor(pos_weight)

    best_val_loss = float("inf")
    stall = 0
    model.train()
    for epoch in range(200):
        optimizer.zero_grad()
        outputs = model(X_t)
        per_sample_loss = criterion(outputs, y_t)
        weight_vec = torch.where(y_t == 1, pos_weight_tensor, torch.tensor(1.0))
        loss = (per_sample_loss * weight_vec).mean()
        loss.backward()
        optimizer.step()
        with torch.no_grad():
            preds = (outputs > 0.5).float()
            acc = (preds == y_t).float().mean().item()
            v_out = model(X_v)
            v_loss = val_criterion(v_out, y_v).item()
            v_preds = (v_out > 0.5).float()
            v_acc = (v_preds == y_v).float().mean().item()
            v_tp = (v_preds * y_v).sum().item()
            v_fn = ((1 - v_preds) * y_v).sum().item()
            v_f1 = 2 * v_tp / (2 * v_tp + v_fn + ((v_preds * (1 - y_v)).sum().item()) + 1e-8)
        print(f"  Epoch {epoch+1:3d} loss={loss.item():.4f} val_loss={v_loss:.4f} val_acc={v_acc:.4f} val_f1={v_f1:.4f}")
        if v_loss < best_val_loss:
            best_val_loss = v_loss
            stall = 0
        else:
            stall += 1
            if stall >= 20:
                print(f"  Early stop at epoch {epoch+1}, best val_loss={best_val_loss:.4f}, final val_f1={v_f1:.4f}")
                break

    model.eval()
    w1 = model.net[0].weight.detach().numpy().T
    b1 = model.net[0].bias.detach().numpy()
    w2 = model.net[2].weight.detach().numpy().T
    b2 = model.net[2].bias.detach().numpy()
    w3 = model.net[4].weight.detach().numpy().T
    b3 = model.net[4].bias.detach().numpy()

    w1_init = numpy_helper.from_array(w1, "fc1_w")
    b1_init = numpy_helper.from_array(b1, "fc1_b")
    w2_init = numpy_helper.from_array(w2, "fc2_w")
    b2_init = numpy_helper.from_array(b2, "fc2_b")
    w3_init = numpy_helper.from_array(w3, "fc3_w")
    b3_init = numpy_helper.from_array(b3, "fc3_b")

    n1 = helper.make_node("Gemm", ["input", "fc1_w", "fc1_b"], ["fc1"], alpha=1.0, beta=1.0, transA=0, transB=0)
    n2 = helper.make_node("Relu", ["fc1"], ["r1"])
    n3 = helper.make_node("Gemm", ["r1", "fc2_w", "fc2_b"], ["fc2"], alpha=1.0, beta=1.0, transA=0, transB=0)
    n4 = helper.make_node("Relu", ["fc2"], ["r2"])
    n5 = helper.make_node("Gemm", ["r2", "fc3_w", "fc3_b"], ["fc3"], alpha=1.0, beta=1.0, transA=0, transB=0)
    n6 = helper.make_node("Sigmoid", ["fc3"], ["output"])

    graph = helper.make_graph(
        [n1, n2, n3, n4, n5, n6], "net",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, DENSE_DIM])],
        [helper.make_tensor_value_info("output", TensorProto.FLOAT, [None, 1])],
        [w1_init, b1_init, w2_init, b2_init, w3_init, b3_init],
    )
    onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 11)])
    with open("model.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    print("\nOK model.onnx exported (opset 11)")


if __name__ == "__main__":
    main()
