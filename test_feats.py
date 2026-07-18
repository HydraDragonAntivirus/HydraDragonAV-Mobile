import os, numpy as np
from train_model import extract_features

ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
mal_dir = r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk'
bens = os.listdir(ben_dir)[:5]
mals = os.listdir(mal_dir)[:5]
for f in bens:
    feats = extract_features(os.path.join(ben_dir, f))
    print(f'ben {f[:30]:30s} mean={feats.mean():.4f} std={feats.std():.4f} max={feats.max():.4f} min={feats.min():.4f}')
for f in mals:
    feats = extract_features(os.path.join(mal_dir, f))
    print(f'mal {f[:30]:30s} mean={feats.mean():.4f} std={feats.std():.4f} max={feats.max():.4f} min={feats.min():.4f}')
