"""Test BOTH buggy (name-only) and fixed (content) features vs onnxruntime."""
import os, sys, zipfile
import numpy as np
import onnxruntime as ort

sys.path.insert(0, '.')

# Manually do name-only extraction (old buggy behavior)
apk = r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk"
from train_model import DENSE_DIM, token, fnv1a

# Name-only features
tokens = set()
with zipfile.ZipFile(apk, 'r') as z:
    for name in z.namelist():
        tokens.add(token('name:', name.encode()))

counts = [0] * DENSE_DIM
for t in tokens:
    bucket = t % DENSE_DIM
    counts[bucket] = min(counts[bucket] + 1, 0xFFFFFFFF)

v_name = np.array([np.log1p(c) for c in counts], dtype=np.float32)
norm = np.sqrt(np.sum(v_name * v_name))
if norm > 0:
    v_name /= norm
print(f"Name-only features: {len(tokens)} tokens")
print(f"  [0..10]: {v_name[:10]}")

# Content-rich features (fixed)
from train_model import extract_features
v_content = extract_features(apk)
print(f"\nContent features:")
print(f"  [0..10]: {v_content[:10]}")

# Run both through ONNX
import onnx
sess = ort.InferenceSession("model.onnx")
input_name = sess.get_inputs()[0].name

py_name = sess.run(['output'], {input_name: v_name.reshape(1,-1).astype(np.float32)})[0]
py_content = sess.run(['output'], {input_name: v_content.reshape(1,-1).astype(np.float32)})[0]

print(f"\nonnxruntime with name-only  features: {py_name[0]:.6f}")
print(f"onnxruntime with content    features: {py_content[0]:.6f}")

model = onnx.load("model.onnx")
for init in model.graph.initializer:
    if init.name == 'fc1_w':
        print(f"\nfc1_w shape: {list(init.dims)}")
        break
