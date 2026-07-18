import onnxruntime as ort, numpy as np, os
from train_model import extract_features

sess = ort.InferenceSession('model.onnx')
ben = extract_features(r'dataset\benign\F-Droid\16-07-2026-14.49\ac.mdiq.Podcini.A_71.apk')
b = sess.run(['output'],{sess.get_inputs()[0].name:ben.reshape(1,-1).astype('f4')})[0][0]
mal = extract_features(os.path.join(r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk',os.listdir(r'dataset\malware\MalwareBazaar\27.06.2026 - 203930_212345\apk')[0]))
m = sess.run(['output'],{sess.get_inputs()[0].name:mal.reshape(1,-1).astype('f4')})[0][0]
ok = "DOGRU" if b < m else "YANLIS"
print(f'benign: {b:.6f}  malware: {m:.6f}  secim: {ok}')
