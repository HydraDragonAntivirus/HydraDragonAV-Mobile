"""
Mevcut model.onnx (opset 18, Squeeze içeriyor) tract-onnx tarafindan
desteklenmiyor. Bu script:
  1. Egitilmis PyTorch modelini yukleri.
  2. BatchNorm'u fc1 agirliklarına fuse eder (eval zamaninda sabit).
  3. Dropout'u cikarir (eval zamaninda identity).
  4. Temiz bir Gemm→Relu→Gemm→Relu→Gemm→Sigmoid grafi ile
     opset 11 ONNX modeli uretir.
  5. Hem ortxruntime hem de tract-onnx ile calisir.

Usage:
    python export_onnx_opset11.py
"""
import numpy as np
import onnx
from onnx import helper, TensorProto, numpy_helper
import torch
import torch.nn as nn
import sys, os

sys.path.insert(0, os.path.dirname(__file__))
from train_model import DENSE_DIM, Net


def main():
    # --- 1. Dummy-train or load weights ---
    # We need a saved checkpoint OR we retrain minimally.
    # Since we only have model.onnx (opset18), we can't load weights directly.
    # Solution: re-export from a freshly trained model.
    # The user should pass --train if they want to retrain, else we error.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', default='dataset',
                        help='Dataset root for retraining (needed for export)')
    parser.add_argument('--checkpoint', default='model_weights.pt',
                        help='Saved PyTorch weights (.pt) to load instead of retraining')
    args = parser.parse_args()

    model = Net()

    if os.path.exists(args.checkpoint):
        print(f"Loading weights from {args.checkpoint}...")
        model.load_state_dict(torch.load(args.checkpoint, map_location='cpu'))
    else:
        print(f"ERROR: {args.checkpoint} not found.")
        print("Please run train_model.py with --save-weights, or")
        print("use the existing model by running: python export_onnx_opset11.py --checkpoint model_weights.pt")
        sys.exit(1)

    _export(model)


def _export(model: nn.Module):
    """Export the model to opset-11 ONNX with BatchNorm fused into fc1."""
    model.eval()

    # ----- Fuse BatchNorm (net[1]) into Linear (net[0]) -----
    # BN: y = (x - mean) / sqrt(var + eps) * gamma + beta
    # After Linear(x): out = x @ W + b
    # Fused: W' = W * scale[:, None],  b' = (b - mean) * scale + beta
    # where scale = gamma / sqrt(var + eps)
    eps      = model.net[1].eps
    bn_mean  = model.net[1].running_mean.detach().numpy()   # [512]
    bn_var   = model.net[1].running_var.detach().numpy()    # [512]
    bn_g     = model.net[1].weight.detach().numpy()         # [512] gamma
    bn_b     = model.net[1].bias.detach().numpy()           # [512] beta
    scale    = bn_g / np.sqrt(bn_var + eps)                 # [512]

    w1_raw   = model.net[0].weight.detach().numpy()         # [512, 2048]
    b1_raw   = model.net[0].bias.detach().numpy()           # [512]
    w1_fused = (w1_raw * scale[:, None]).T                  # [2048, 512]
    b1_fused = (b1_raw - bn_mean) * scale + bn_b           # [512]

    # net[2] = ReLU, net[3] = Dropout (identity at eval)
    w2 = model.net[4].weight.detach().numpy().T             # [512, 128]
    b2 = model.net[4].bias.detach().numpy()                 # [128]
    # net[5] = ReLU, net[6] = Dropout (identity at eval)
    w3 = model.net[7].weight.detach().numpy().T             # [128, 1]
    b3 = model.net[7].bias.detach().numpy()                 # [1]

    # Verify numerically against PyTorch
    with torch.no_grad():
        dummy = torch.randn(4, DENSE_DIM)
        pt_out = model(dummy).numpy()                       # [4]
        # Manual fused forward
        x = dummy.numpy() @ w1_fused + b1_fused            # [4, 512]
        x = np.maximum(x, 0)                               # ReLU
        x = x @ w2 + b2                                    # [4, 128]
        x = np.maximum(x, 0)                               # ReLU
        x = x @ w3 + b3                                    # [4, 1]
        x = 1 / (1 + np.exp(-x))                           # Sigmoid
        x = x[:, 0]                                        # [4]
    diff = np.abs(pt_out - x).max()
    print(f"Fused BN verification — max abs diff vs PyTorch: {diff:.2e}")
    if diff > 1e-4:
        print("WARNING: large numerical difference after fusion!")

    # ----- Build ONNX graph (opset 11, Gemm→Relu→Gemm→Relu→Gemm→Sigmoid) -----
    inits = [
        numpy_helper.from_array(w1_fused.astype(np.float32), 'fc1_w'),
        numpy_helper.from_array(b1_fused.astype(np.float32), 'fc1_b'),
        numpy_helper.from_array(w2.astype(np.float32),        'fc2_w'),
        numpy_helper.from_array(b2.astype(np.float32),        'fc2_b'),
        numpy_helper.from_array(w3.astype(np.float32),        'fc3_w'),
        numpy_helper.from_array(b3.astype(np.float32),        'fc3_b'),
    ]
    nodes = [
        helper.make_node('Gemm',    ['input','fc1_w','fc1_b'], ['fc1'], alpha=1.0, beta=1.0, transA=0, transB=0),
        helper.make_node('Relu',    ['fc1'],                    ['r1']),
        helper.make_node('Gemm',    ['r1','fc2_w','fc2_b'],    ['fc2'], alpha=1.0, beta=1.0, transA=0, transB=0),
        helper.make_node('Relu',    ['fc2'],                    ['r2']),
        helper.make_node('Gemm',    ['r2','fc3_w','fc3_b'],    ['fc3'], alpha=1.0, beta=1.0, transA=0, transB=0),
        helper.make_node('Sigmoid', ['fc3'],                    ['output']),
    ]
    graph = helper.make_graph(
        nodes, 'hydradragon_ml',
        [helper.make_tensor_value_info('input',  TensorProto.FLOAT, [None, DENSE_DIM])],
        [helper.make_tensor_value_info('output', TensorProto.FLOAT, [None, 1])],
        inits,
    )
    onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 11)])
    onnx.checker.check_model(onnx_model)
    with open('model.onnx', 'wb') as f:
        f.write(onnx_model.SerializeToString())
    print('OK model.onnx exported — opset 11, BN fused into fc1')
    print('  Input:  [batch, {}]'.format(DENSE_DIM))
    print('  Output: [batch, 1]  (tract-onnx compatible)')

    # ----- Quick onnxruntime sanity check -----
    try:
        import onnxruntime as ort
        sess = ort.InferenceSession('model.onnx')
        dummy_np = np.zeros((1, DENSE_DIM), dtype=np.float32)
        out = sess.run(['output'], {sess.get_inputs()[0].name: dummy_np})
        print(f'  onnxruntime check: output shape={out[0].shape}  value={out[0][0,0]:.6f}')
    except Exception as e:
        print(f'  onnxruntime check skipped: {e}')


if __name__ == '__main__':
    main()
