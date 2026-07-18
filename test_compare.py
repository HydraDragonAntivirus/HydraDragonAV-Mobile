"""Compare onnxruntime vs tract-onnx with EXACT same features."""
import os, sys
import numpy as np
import onnxruntime as ort

sys.path.insert(0, '.')
from train_model import extract_features

# 1. Extract features from ONE APK
apk = r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk"
feats = extract_features(apk)
print(f"Features shape: {feats.shape}")
print(f"Features[0..10]: {feats[:10]}")
print(f"Norm: {np.sqrt(np.sum(feats*feats)):.6f}")

# 2. Predict with onnxruntime
sess = ort.InferenceSession("model.onnx")
input_name = sess.get_inputs()[0].name
onnx_input = feats.reshape(1, -1).astype(np.float32)
py_out = sess.run(['output'], {input_name: onnx_input})[0]
print(f"\nonnxruntime output: {py_out[0,0]:.6f}")

# 3. Save features to a binary file for Rust to read
feats.astype(np.float32).tofile("test_features.bin")
print(f"\nFeatures saved to test_features.bin ({feats.nbytes} bytes)")

# 4. Print model info
print(f"\nModel input: {sess.get_inputs()[0]}")
print(f"Model output: {sess.get_outputs()[0]}")
