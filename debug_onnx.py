"""Compare PyTorch model output vs ONNX model output on same APK features."""
import onnx
import numpy as np
import onnxruntime as ort
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from train_model import Net, DENSE_DIM, extract_features

# 1. Find a few APKs
dataset_root = "dataset"
apk_paths = []
for root, dirs, files in os.walk(dataset_root):
    for fname in files:
        if fname.lower().endswith('.apk') and 'invalid' not in root.lower():
            apk_paths.append(os.path.join(root, fname))
            if len(apk_paths) >= 10:
                break
    if len(apk_paths) >= 10:
        break

print(f"Using {len(apk_paths)} APKs")

# 2. Load ONNX and inspect weights
onnx_model = onnx.load("model.onnx")
print(f"\n=== ONNX Graph ===")
print(f"IR version: {onnx_model.ir_version}")
print(f"Opset: {onnx_model.opset_import[0].version}")

print("\n=== ONNX Initializers (weights) ===")
for init in onnx_model.graph.initializer:
    arr = onnx.numpy_helper.to_array(init)
    print(f"  {init.name}: shape={list(init.dims)} min={arr.min():.6f} max={arr.max():.6f} mean={arr.mean():.6f} std={arr.std():.6f}")

print("\n=== ONNX Nodes ===")
for node in onnx_model.graph.node:
    print(f"  {node.op_type:10s} {node.input} -> {node.output}")

# 3. Run ONNX inference
sess = ort.InferenceSession("model.onnx")
input_name = sess.get_inputs()[0].name
output_name = sess.get_outputs()[0].name

print(f"\nInput:  {sess.get_inputs()[0].name} shape={sess.get_inputs()[0].shape}")
print(f"Output: {sess.get_outputs()[0].name} shape={sess.get_outputs()[0].shape}")

print("\n=== ONNX inference on APKs ===")
for apk_path in apk_paths:
    feats = extract_features(apk_path)
    if feats is None:
        continue
    onnx_input = feats.reshape(1, -1).astype(np.float32)
    onnx_out = sess.run([output_name], {input_name: onnx_input})[0]
    onnx_conf = onnx_out[0, 0]
    label = "MALWARE" if 'malware' in apk_path.lower() else "BENIGN"
    print(f"  {label:8s} conf={onnx_conf:.6f}  {os.path.basename(apk_path)[:60]}")

# 4. Manual forward pass using extracted weights
print("\n=== Manual forward pass ===")
w = {}
b = {}
for init in onnx_model.graph.initializer:
    arr = onnx.numpy_helper.to_array(init)
    if init.name.endswith('_w'):
        w[init.name] = arr
    elif init.name.endswith('_b'):
        b[init.name] = arr

# Manual forward pass: Gemm with transA=0, transB=0 -> y = x @ W + b
for apk_path in apk_paths[:3]:
    feats = extract_features(apk_path)
    if feats is None:
        continue
    
    x = feats.reshape(1, -1)  # (1, 256)
    
    # Layer 1: Gemm(input, fc1_w, fc1_b) -> x @ w1 + b1
    h1 = x @ w['fc1_w'] + b['fc1_b']  # (1, 256) @ (256, 128) + (128,) = (1, 128)
    r1 = np.maximum(0, h1)  # ReLU
    
    # Layer 2: Gemm(r1, fc2_w, fc2_b) -> r1 @ w2 + b2
    h2 = r1 @ w['fc2_w'] + b['fc2_b']  # (1, 128) @ (128, 64) + (64,) = (1, 64)
    r2 = np.maximum(0, h2)  # ReLU
    
    # Layer 3: Gemm(r2, fc3_w, fc3_b) -> r2 @ w3 + b3
    h3 = r2 @ w['fc3_w'] + b['fc3_b']  # (1, 64) @ (64, 1) + (1,) = (1, 1)
    out = 1.0 / (1.0 + np.exp(-h3))  # Sigmoid
    
    label = "MALWARE" if 'malware' in apk_path.lower() else "BENIGN"
    onnx_input = feats.reshape(1, -1).astype(np.float32)
    onnx_out = sess.run([output_name], {input_name: onnx_input})[0]
    print(f"  {label:8s} manual={out[0,0]:.6f} onnxruntime={onnx_out[0,0]:.6f}  {os.path.basename(apk_path)[:50]}")
    print(f"    h3 (logit)={h3[0,0]:.6f}")
