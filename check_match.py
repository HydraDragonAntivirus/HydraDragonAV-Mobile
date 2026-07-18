import subprocess, json, numpy as np
from train_model import extract_features

apk = r'dataset\benign\F-Droid\16-07-2026-14.49\a2dp.Vol_169.apk'

py_feats = extract_features(apk)
print(f'Python: mean={py_feats.mean():.6f} sum={py_feats.sum():.6f}')

result = subprocess.run(
    ['cargo', 'run', '--release', '--bin', 'debug_features', '--', apk],
    capture_output=True, text=True, cwd=r'hydradragonml'
)
line = [l for l in result.stdout.split('\n') if 'dense' in l.lower() or 'confidence' in l.lower()]
for l in line: print(l)
