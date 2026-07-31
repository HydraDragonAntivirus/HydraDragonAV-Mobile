"""HydraDragonML — EmbeddingBag + MLP with learned vocabulary.

Replaces old FNV hash → 2048 buckets approach:
  - No hash collisions: each token maps to a learned embedding
  - EmbeddingBag handles variable-length token sequences natively
  - Far fewer parameters, better generalization
"""

import json
import os
import re
import sys
import zipfile
from collections import Counter

import numpy as np
import torch
import torch.nn as nn
from onnx import helper, TensorProto, numpy_helper

MIN_STR_LEN = 5
MAX_TOKENS = 120_000
MAX_ENTRY_SCAN = 16 * 1024 * 1024
VOCAB_SIZE = 20000
EMBED_DIM = 64

_ASCII_RE = re.compile(b'[\x20-\x7e]{5,}')
_UTF16_RE = re.compile(b'(?:[\x20-\x7e]\x00){5,}')


def sub_tokenize(text: str) -> list[str]:
    out = []
    for part in re.split(r'[./;:\-\\_]+', text):
        if len(part) >= 2:
            out.append(part.lower())
    return out


def harvest_strings(data: bytes, tokens: list[str]):
    for m in _ASCII_RE.finditer(data):
        for t in sub_tokenize(m.group(0).decode('ascii', errors='replace')):
            tokens.append(t)
            if len(tokens) >= MAX_TOKENS:
                return
    for m in _UTF16_RE.finditer(data):
        decoded = m.group(0)[::2].decode('ascii', errors='replace')
        for t in sub_tokenize(decoded):
            tokens.append(t)
            if len(tokens) >= MAX_TOKENS:
                return


def extract_tokens(apk_path: str) -> list[str] | None:
    try:
        z = zipfile.ZipFile(apk_path, 'r')
        namelist = z.namelist()
    except Exception:
        return None
    tokens: list[str] = []
    for name in namelist:
        if len(tokens) >= MAX_TOKENS:
            break
        for t in sub_tokenize(name):
            tokens.append(t)
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
        harvest_strings(data, tokens)
    z.close()
    return tokens if tokens else None


def build_vocab(dataset_root: str) -> dict[str, int]:
    import concurrent.futures
    from tqdm import tqdm
    apks = []
    for root, dirs, files in os.walk(dataset_root):
        for fname in files:
            if not fname.lower().endswith('.apk') or 'invalid' in root.lower():
                continue
            apks.append(os.path.join(root, fname))
    counter: Counter = Counter()
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(1, os.cpu_count() or 4)) as pool:
        for toks in tqdm(pool.map(_extract_tokens_worker, apks), total=len(apks), desc='Vocab'):
            if toks:
                counter.update(set(toks))
    most_common = counter.most_common(VOCAB_SIZE - 1)
    vocab = {'<UNK>': 0}
    for i, (token, _freq) in enumerate(most_common, start=1):
        vocab[token] = i
    print(f'  vocabulary: {len(vocab)} tokens (from {len(counter)} unique)')
    with open('vocab.json', 'w', encoding='utf-8') as f:
        json.dump(vocab, f, ensure_ascii=False)
    print('  vocab.json saved')
    return vocab


def _extract_tokens_worker(path: str):
    return extract_tokens(path)


def encode_apk(apk_path: str, vocab: dict[str, int]) -> np.ndarray | None:
    toks = extract_tokens(apk_path)
    if toks is None:
        return None
    return np.array([vocab.get(t, 0) for t in toks], dtype=np.int64)


def gather_dataset(dataset_root: str, vocab: dict[str, int]):
    import concurrent.futures
    from tqdm import tqdm
    jobs = []
    for root, dirs, files in os.walk(dataset_root):
        for fname in files:
            if not fname.lower().endswith('.apk') or 'invalid' in root.lower():
                continue
            label = 1 if 'malware' in root.lower() else 0
            jobs.append((os.path.join(root, fname), label, vocab))
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(1, os.cpu_count() or 4)) as pool:
        for result in tqdm(pool.map(_encode_one, jobs), total=len(jobs), desc='Encoding'):
            if result is not None:
                results.append(result)
    return results


def _encode_one(args):
    path, label, vocab = args
    indices = encode_apk(path, vocab)
    return (indices, label) if indices is not None else None


class EmbeddingBagMLP(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int):
        super().__init__()
        self.emb = nn.EmbeddingBag(vocab_size, embed_dim, mode='mean')
        self.fc1 = nn.Linear(embed_dim, 32)
        self.fc2 = nn.Linear(32, 1)
        self.dropout = nn.Dropout(0.2)

    def forward(self, indices, offsets):
        x = self.emb(indices, offsets)
        x = self.dropout(torch.relu(self.fc1(x)))
        return self.fc2(x).squeeze(-1)


def train(dataset_root: str):
    print(f'Building vocabulary from {dataset_root}...')
    vocab = build_vocab(dataset_root)
    print('Encoding APKs...')
    encoded = gather_dataset(dataset_root, vocab)
    print(f'  {len(encoded)} APKs encoded')
    if len(encoded) == 0:
        print('ERROR: no APKs found')
        return None, None

    rng = np.random.RandomState(42)
    rng.shuffle(encoded)
    split = int(len(encoded) * 0.8)
    train_data, val_data = encoded[:split], encoded[split:]

    n_mal = sum(l for _, l in train_data)
    n_pos = len(train_data) - n_mal
    print(f'  train: {len(train_data)} ({n_mal} malware, {n_pos} benign)')
    print(f'  val:   {len(val_data)}')

    model = EmbeddingBagMLP(len(vocab), EMBED_DIM)
    pos_weight = torch.tensor(n_pos / max(n_mal, 1))
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    val_criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)

    batch_size = 32
    rng.shuffle(train_data)
    train_batches = [train_data[i:i + batch_size] for i in range(0, len(train_data), batch_size)]
    val_batches = [val_data[i:i + batch_size] for i in range(0, len(val_data), batch_size)]

    def collate(batch):
        indices_list = [torch.from_numpy(indices) for indices, _ in batch]
        labels = torch.tensor([l for _, l in batch], dtype=torch.float32)
        all_indices = torch.cat(indices_list)
        offsets = torch.zeros(len(indices_list), dtype=torch.long)
        cum = 0
        for i, inds in enumerate(indices_list):
            offsets[i] = cum
            cum += len(inds)
        return all_indices, offsets, labels

    best_val_loss = float('inf')
    stall = 0
    for epoch in range(300):
        model.train()
        total_loss = 0.0
        for batch in train_batches:
            indices, offsets, labels = collate(batch)
            optimizer.zero_grad()
            logits = model(indices, offsets)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        model.eval()
        v_loss = 0.0
        v_correct = 0
        v_total = 0
        v_tp = v_fn = v_fp = 0
        with torch.no_grad():
            for batch in val_batches:
                indices, offsets, labels = collate(batch)
                logits = model(indices, offsets)
                v_loss += val_criterion(logits, labels).item()
                preds = (torch.sigmoid(logits) > 0.5).float()
                v_correct += (preds == labels).sum().item()
                v_total += len(labels)
                v_tp += ((preds == 1) & (labels == 1)).sum().item()
                v_fn += ((preds == 0) & (labels == 1)).sum().item()
                v_fp += ((preds == 1) & (labels == 0)).sum().item()

        avg_loss = total_loss / len(train_batches)
        avg_vloss = v_loss / len(val_batches)
        v_acc = v_correct / max(v_total, 1)
        v_f1 = 2 * v_tp / max(2 * v_tp + v_fn + v_fp, 1)
        print(f'  Epoch {epoch+1:3d} loss={avg_loss:.4f} val_loss={avg_vloss:.4f} '
              f'acc={v_acc:.4f} f1={v_f1:.4f}')
        scheduler.step(avg_vloss)
        if avg_vloss < best_val_loss:
            best_val_loss = avg_vloss
            torch.save(model.state_dict(), 'model_weights.pt')
            stall = 0
        else:
            stall += 1
            if stall >= 25:
                print(f'  Early stop at epoch {epoch+1}')
                break
    return model, vocab


def export_onnx(model: EmbeddingBagMLP, vocab: dict[str, int]):
    model.eval()
    inits = [
        numpy_helper.from_array(model.emb.weight.detach().numpy().astype(np.float32), 'emb_w'),
        numpy_helper.from_array(model.fc1.weight.detach().numpy().T.astype(np.float32), 'fc1_w'),
        numpy_helper.from_array(model.fc1.bias.detach().numpy().astype(np.float32), 'fc1_b'),
        numpy_helper.from_array(model.fc2.weight.detach().numpy().T.astype(np.float32), 'fc2_w'),
        numpy_helper.from_array(model.fc2.bias.detach().numpy().astype(np.float32), 'fc2_b'),
    ]
    nodes = [
        helper.make_node('Gather', ['emb_w', 'input'], ['gathered'], axis=0),
        helper.make_node('ReduceMean', ['gathered'], ['pooled'], axes=[0], keepdims=0),
        helper.make_node('Gemm', ['pooled', 'fc1_w', 'fc1_b'], ['fc1'], alpha=1.0, beta=1.0),
        helper.make_node('Relu', ['fc1'], ['r1']),
        helper.make_node('Gemm', ['r1', 'fc2_w', 'fc2_b'], ['fc2'], alpha=1.0, beta=1.0),
        helper.make_node('Sigmoid', ['fc2'], ['output']),
    ]
    graph = helper.make_graph(
        nodes, 'hdragon_ml',
        [helper.make_tensor_value_info('input', TensorProto.INT64, [None])],
        [helper.make_tensor_value_info('output', TensorProto.FLOAT, [1])],
        inits,
    )
    onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 11)])
    with open('model.onnx', 'wb') as f:
        f.write(onnx_model.SerializeToString())
    with open('vocab.json', 'w', encoding='utf-8') as f:
        json.dump(vocab, f, ensure_ascii=False)
    print(f'\nOK model.onnx exported ({len(vocab)} vocab, {EMBED_DIM} embed_dim)')


def main():
    args = sys.argv[1:]
    export_only = '--export-only' in args
    dataset = args[0] if args and args[0] != '--export-only' else 'dataset'
    if export_only:
        print(f'HydraDragonML — export only from {dataset}')
        with open('vocab.json', 'r') as f:
            vocab = json.load(f)
        model = EmbeddingBagMLP(len(vocab), EMBED_DIM)
        state = torch.load('model_weights.pt', map_location='cpu', weights_only=True)
        model.load_state_dict(state)
        export_onnx(model, vocab)
        return
    print(f'HydraDragonML — training from {dataset}')
    model, vocab = train(dataset)
    if model is None:
        return
    export_onnx(model, vocab)


if __name__ == '__main__':
    main()
