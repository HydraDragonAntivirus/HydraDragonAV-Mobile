import os, numpy as np
from train_model import extract_features

ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
f1 = os.path.join(ben_dir, os.listdir(ben_dir)[0])
f2 = os.path.join(ben_dir, os.listdir(ben_dir)[1])
a = extract_features(f1)
b = extract_features(f2)
print('max:', a.max(), 'min:', a.min())
print('first 10:', a[:10])
print('first 10 diff:', (a-b)[:10])
print('|a-b|:', np.linalg.norm(a-b))
print('bins 100-110:', a[100:110])
print('unique values:', len(set(a)))
