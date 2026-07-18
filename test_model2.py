import onnxruntime as ort, numpy as np, os, random
from train_model import extract_features

sess = ort.InferenceSession('model.onnx')
ben_dir = r'dataset\benign\F-Droid\16-07-2026-14.49'
mal_dir = r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk'
bens = random.sample(os.listdir(ben_dir), 10)
mals = random.sample(os.listdir(mal_dir), 10)

ben_scores = []
for f in bens:
    fe = extract_features(os.path.join(ben_dir, f))
    out = sess.run(['output'],{sess.get_inputs()[0].name:fe.reshape(1,-1).astype('f4')})[0][0][0]
    ben_scores.append(out)

mal_scores = []
for f in mals:
    fe = extract_features(os.path.join(mal_dir, f))
    out = sess.run(['output'],{sess.get_inputs()[0].name:fe.reshape(1,-1).astype('f4')})[0][0][0]
    mal_scores.append(out)

ben_arr = np.array(ben_scores)
mal_arr = np.array(mal_scores)
print(f'benign:  mean={ben_arr.mean():.4f} min={ben_arr.min():.4f} max={ben_arr.max():.4f}')
print(f'malware: mean={mal_arr.mean():.4f} min={mal_arr.min():.4f} max={mal_arr.max():.4f}')
print(f'ben < mal: {np.mean(ben_arr < mal_arr)*100:.1f}%')
print(f'ben < 0.5: {np.mean(ben_arr < 0.5)*100:.1f}%  mal > 0.5: {np.mean(mal_arr > 0.5)*100:.1f}%')
