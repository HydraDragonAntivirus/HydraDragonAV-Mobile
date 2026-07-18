"""Analyze feature variation with different DENSE_DIM x MAX_TOKENS combinations."""
import os, sys
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

dataset_root = "dataset"
benign_paths = []
malware_paths = []
for root, dirs, files in os.walk(dataset_root):
    for fname in files:
        if not fname.lower().endswith('.apk') or 'invalid' in root.lower():
            continue
        path = os.path.join(root, fname)
        if 'malware' in root.lower() and len(malware_paths) < 20:
            malware_paths.append(path)
        elif 'benign' in root.lower() and len(benign_paths) < 20:
            benign_paths.append(path)

# Test scenarios
from train_model import extract_features as extract_orig

# We need to test with different MAX_TOKENS values by monkey-patching
def test_config(dense_dim, max_tokens, label):
    import train_model as tm
    old_dim = tm.DENSE_DIM
    old_max = tm.MAX_TOKENS
    tm.DENSE_DIM = dense_dim
    tm.MAX_TOKENS = max_tokens
    
    # Need to reimport extract_features... 
    # Instead, just manually compute
    import importlib
    importlib.reload(tm)
    from train_model import extract_features
    
    benign_feats = []
    malware_feats = []
    for path in benign_paths:
        f = extract_features(path)
        if f is not None:
            benign_feats.append(f)
    for path in malware_paths:
        f = extract_features(path)
        if f is not None:
            malware_feats.append(f)
    
    if len(benign_feats) < 2 or len(malware_feats) < 2:
        print(f"  {label}: not enough samples")
        tm.DENSE_DIM = old_dim
        tm.MAX_TOKENS = old_max
        return
    
    benign_arr = np.array(benign_feats)
    malware_arr = np.array(malware_feats)
    
    # Compute between-class variation vs within-class variation
    benign_mean = benign_arr.mean(axis=0)
    malware_mean = malware_arr.mean(axis=0)
    
    # Separability: L2 distance between class means / avg within-class std
    sep = np.linalg.norm(benign_mean - malware_mean)
    benign_std = benign_arr.std(axis=0).mean()
    malware_std = malware_arr.std(axis=0).mean()
    
    # Zero count
    benign_zeros = (benign_arr == 0).sum(axis=1).mean()
    malware_zeros = (malware_arr == 0).sum(axis=1).mean()
    
    print(f"  {label:35s} sep={sep:.4f} b_std={benign_std:.4f} m_std={malware_std:.4f} b_zeros={benign_zeros:.0f} m_zeros={malware_zeros:.0f}")
    if sep > 0:
        print(f"    Cohen's d≈{sep / np.sqrt((benign_std**2 + malware_std**2)/2):.4f}")
    
    tm.DENSE_DIM = old_dim
    tm.MAX_TOKENS = old_max

# Test various configs
import train_model as tm

# Save original
orig_dim = tm.DENSE_DIM
orig_max = tm.MAX_TOKENS

# 1. 256 dim x various MAX_TOKENS
test_config(256, 120000, "256-dim, 120k max")
test_config(256, 5000, "256-dim, 5k max")
test_config(256, 1000, "256-dim, 1k max")

# 2. 4096 dim x various MAX_TOKENS
test_config(4096, 120000, "4096-dim, 120k max")
test_config(4096, 5000, "4096-dim, 5k max")
test_config(4096, 1000, "4096-dim, 1k max")

# Restore
tm.DENSE_DIM = orig_dim
tm.MAX_TOKENS = orig_max
