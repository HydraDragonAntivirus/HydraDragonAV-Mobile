import os, numpy as np
from train_model import extract_features

ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
f = os.path.join(ben_dir, os.listdir(ben_dir)[0])
fe = extract_features(f)
print('norm:', np.linalg.norm(fe))
print('sum:', fe.sum())
print('sum_sq:', (fe*fe).sum())
print('mean:', fe.mean())
