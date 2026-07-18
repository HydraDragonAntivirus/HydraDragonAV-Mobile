import os, numpy as np
from train_model import extract_features

ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
mal_dir = r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk'

b = np.array([extract_features(os.path.join(ben_dir, f)) for f in os.listdir(ben_dir)[:10]])
m = np.array([extract_features(os.path.join(mal_dir, f)) for f in os.listdir(mal_dir)[:10]])

print(f'benign mean: {b.mean():.4f} std: {b.mean(1).std():.4f}')
print(f'malware mean: {m.mean():.4f} std: {m.mean(1).std():.4f}')
print(f'||b_avg - m_avg||_2: {np.linalg.norm(b.mean(0)-m.mean(0)):.4f}')
sep = abs(b.mean()-m.mean())/(b.std()+m.std()+1e-8)
print(f'class separation (mean diff / pooled std): {sep:.4f}')
