"""Test feature variation with reduced MAX_TOKENS."""
import os, sys
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

# Monkey-patch MAX_TOKENS
import train_model
train_model.MAX_TOKENS = 2000
from train_model import extract_features

dataset_root = "dataset"
benign = []
malware = []
for root, dirs, files in os.walk(dataset_root):
    for fname in files:
        if not fname.lower().endswith('.apk') or 'invalid' in root.lower():
            continue
        path = os.path.join(root, fname)
        if 'malware' in root.lower() and len(malware) < 10:
            malware.append(path)
        elif 'benign' in root.lower() and len(benign) < 10:
            benign.append(path)
        if len(benign) >= 10 and len(malware) >= 10:
            break

print(f"MAX_TOKENS=2000")
print(f"{'':60s} {'min':>8s} {'max':>8s} {'std':>8s} {'zeros':>6s}")
for label, samples in [("BENIGN", benign), ("MALWARE", malware)]:
    for path in samples:
        feats = extract_features(path)
        if feats is None:
            continue
        zeros = sum(1 for v in feats if v == 0.0)
        print(f"  {label:7s} {os.path.basename(path)[:50]:50s} {feats.min():8.4f} {feats.max():8.4f} {feats.std():8.6f} {zeros:6d}")
