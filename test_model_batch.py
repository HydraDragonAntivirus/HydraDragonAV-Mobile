import onnxruntime as ort, numpy as np, os, random
from train_model import extract_features

sess = ort.InferenceSession('model.onnx')
ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
mal_dir = r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk'
bens = random.sample(os.listdir(ben_dir), 5)
mals = random.sample(os.listdir(mal_dir), 5)

for f in bens:
    fe = extract_features(os.path.join(ben_dir, f))
    out = sess.run(['output'],{sess.get_inputs()[0].name:fe.reshape(1,-1).astype('f4')})[0][0]
    print(f'ben {f[:35]:35s} -> {out:.4f}')

for f in mals:
    fe = extract_features(os.path.join(mal_dir, f))
    out = sess.run(['output'],{sess.get_inputs()[0].name:fe.reshape(1,-1).astype('f4')})[0][0]
    print(f'mal {f[:35]:35s} -> {out:.4f}')
