"""Compare Python feature extraction vs Rust for the same APK, and ONNX output."""
import os
import sys
import numpy as np
import onnxruntime as ort

sys.path.insert(0, os.path.dirname(__file__))
from train_model import DENSE_DIM, extract_features

# Same APK paths as the Rust debug binary
apk_paths = [
    r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk",
    r"C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAV-Mobile\dataset\benign\F-Droid\16-07-2026-14.49\a2dp.Vol_169.apk",
]

sess = ort.InferenceSession("model.onnx")
input_name = sess.get_inputs()[0].name

for apk_path in apk_paths:
    if not os.path.exists(apk_path):
        print(f"SKIP: {apk_path} not found")
        continue
    
    feats = extract_features(apk_path)
    if feats is None:
        print(f"ERROR: extract returned None for {apk_path}")
        continue
    
    print(f"=== {os.path.basename(apk_path)} ===")
    print(f"  dense[0..10]: {' '.join(f'{v:.4f}' for v in feats[:10])}")
    print(f"  dense[246..256]: {' '.join(f'{v:.4f}' for v in feats[246:256])}")
    norm = np.sqrt(np.sum(feats * feats))
    print(f"  L2 norm: {norm:.6f}")
    
    # ONNX inference
    onnx_input = feats.reshape(1, -1).astype(np.float32)
    onnx_out = sess.run(['output'], {input_name: onnx_input})[0]
    print(f"  ONNX confidence: {onnx_out[0,0]:.6f}")
    
    # Also compute with PyTorch model for comparison
    import torch
    from train_model import Net
    model = Net()
    with torch.no_grad():
        model.eval()
        pt_out = model(torch.from_numpy(feats.reshape(1, -1).astype(np.float32)))
        print(f"  PyTorch confidence: {pt_out.item():.6f}")
