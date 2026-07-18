import os, numpy as np
from train_model import extract_features

ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
mal_dir = r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk'

bens = os.listdir(ben_dir)[:3]
for f in bens:
    fe = extract_features(os.path.join(ben_dir, f))
    print(f'{f[:40]:40s} mean={fe.mean():.4f} sum={fe.sum():.2f} nonzero={(fe>0).sum()}')

mal_dir2 = r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk'
mals = os.listdir(mal_dir2)[:3]
for f in mals:
    fe = extract_features(os.path.join(mal_dir2, f))
    print(f'{f[:40]:40s} mean={fe.mean():.4f} sum={fe.sum():.2f} nonzero={(fe>0).sum()}')
