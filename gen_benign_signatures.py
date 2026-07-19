"""
gen_benign_signatures.py
Builds a content-based whitelist (MinHash signatures) from benign APKs.

For each APK:
  1. Extract token set (same logic as train_model.py)
  2. Compute 64-value MinHash signature with NUMPY (vectorized, fast)
  3. Group by package name (from binary AndroidManifest.xml)
  4. Write to app/src/main/assets/scan/benign_signatures.bin

Binary format:
  u32: package count
  For each package:
    u8:  package name length
    N bytes: package name (UTF-8)
    u32: signature count for this package
    For each signature:
      64 x u64: MinHash values

Usage:
    python gen_benign_signatures.py [dataset/benign]
"""

import os
import sys
import struct
import zipfile
import concurrent.futures
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import train_model as tm

MAX_TOKENS    = tm.MAX_TOKENS
MAX_ENTRY_SCAN = tm.MAX_ENTRY_SCAN
FNV_PRIME     = np.uint64(tm.FNV_PRIME)

# MinHash: 64 permutations
K_HASHES = 64
_PERM_I  = np.arange(K_HASHES, dtype=np.uint64)  # [0, 1, 2, ..., 63]


# ── AXML package name parser ────────────────────────────────────────────────
def _u16(d, o): return struct.unpack_from("<H", d, o)[0]
def _u32(d, o): return struct.unpack_from("<I", d, o)[0]

def get_axml_package_name(data: bytes):
    """Extract package name from binary AndroidManifest.xml (AXML)."""
    try:
        if len(data) < 36 or _u16(data, 0) != 0x0003:
            return None
        POOL = 8
        if _u16(data, POOL) != 0x0001:
            return None
        pool_hdr_size = _u16(data, POOL + 2)
        pool_size     = _u32(data, POOL + 4)
        str_count     = _u32(data, POOL + 8)
        flags         = _u32(data, POOL + 16)
        str_start     = _u32(data, POOL + 20)
        is_utf8       = bool(flags & (1 << 8))
        offsets_base  = POOL + pool_hdr_size
        str_data_base = POOL + str_start

        def read_str(idx):
            if idx >= str_count:
                return ''
            rel = _u32(data, offsets_base + idx * 4)
            p = str_data_base + rel
            if is_utf8:
                n = data[p]; p += 1
                if n & 0x80: n = ((n & 0x7F) << 8) | data[p]; p += 1
                n = data[p]; p += 1
                if n & 0x80: n = ((n & 0x7F) << 8) | data[p]; p += 1
                return data[p:p + n].decode('utf-8', errors='ignore')
            else:
                n = _u16(data, p); p += 2
                if n & 0x8000: n = ((n & 0x7FFF) << 16) | _u16(data, p); p += 2
                return data[p:p + n * 2].decode('utf-16-le', errors='ignore')

        off = POOL + pool_size
        guard = 0
        while off + 8 <= len(data) and guard < 100_000:
            guard += 1
            ctype = _u16(data, off)
            csize = _u32(data, off + 4)
            if csize == 0:
                break
            if ctype == 0x0102:  # RES_XML_START_ELEMENT
                name_idx   = _u32(data, off + 20)
                attr_start = _u16(data, off + 24)
                attr_count = _u16(data, off + 28)
                if read_str(name_idx) == 'manifest':
                    abase = off + 16 + attr_start
                    for i in range(min(attr_count, 256)):
                        a = abase + i * 20
                        if a + 20 > len(data):
                            break
                        aname = _u32(data, a + 4)
                        if read_str(aname) == 'package':
                            raw = _u32(data, a + 8)
                            idx = raw if raw != 0xFFFF_FFFF else _u32(data, a + 16)
                            return read_str(idx) or None
            off += csize
    except Exception:
        pass
    return None


# ── MinHash (numpy vectorized) ───────────────────────────────────────────────
def minhash(tokens: set) -> np.ndarray:
    """Compute 64-value MinHash signature.

    For each permutation i:  h_i(t) = (t XOR i) * FNV_PRIME  (mod 2^64)
    All permutations are computed in one NumPy operation.
    """
    if not tokens:
        return np.zeros(K_HASHES, dtype=np.uint64)
    arr = np.fromiter(tokens, dtype=np.uint64, count=len(tokens))  # [N]
    # Broadcast: arr[:, None] XOR _PERM_I[None, :]  -> [N, K]
    h = (arr[:, None] ^ _PERM_I[None, :]) * FNV_PRIME  # wraps mod 2^64 automatically
    return h.min(axis=0)  # [K]


# ── Token extraction (one APK) ───────────────────────────────────────────────
def _process_apk(apk_path: str):
    """Called in a worker process.  Returns (pkg_name, minhash_array) or None."""
    try:
        z = zipfile.ZipFile(apk_path, 'r')
        namelist = z.namelist()
    except Exception:
        return None

    tokens = set()
    manifest_data = None
    for name in namelist:
        if len(tokens) >= MAX_TOKENS:
            break
        tokens.add(tm._token_fast('name:', name.encode()))
        lname = name.lower()
        scan = (lname == 'androidmanifest.xml' or lname == 'resources.arsc'
                or lname.endswith('.dex') or lname.startswith('meta-inf/'))
        if not scan:
            continue
        try:
            with z.open(name) as f:
                data = f.read(MAX_ENTRY_SCAN) or b''
        except Exception:
            continue
        if lname == 'androidmanifest.xml':
            manifest_data = data
            prefix = 'manifest:'
        elif lname.endswith('.dex'):
            prefix = 'dex:'
        else:
            prefix = 'res:'
        tm.harvest_strings(data, prefix, tokens)
    z.close()

    if not tokens or manifest_data is None:
        return None

    pkg = get_axml_package_name(manifest_data)
    if not pkg:
        return None

    sig = minhash(tokens)
    return pkg, sig.tolist()


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    try:
        from tqdm import tqdm
    except ImportError:
        tqdm = lambda x, **kw: x

    dataset_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('dataset/benign')
    if not dataset_root.exists():
        print(f'ERROR: {dataset_root} does not exist.', file=sys.stderr)
        sys.exit(1)

    jobs = [
        str(Path(root) / fname)
        for root, _, files in os.walk(dataset_root)
        for fname in files
        if fname.lower().endswith('.apk')
    ]
    print(f'Found {len(jobs)} APKs in {dataset_root}')

    pkg_signatures: dict[str, list] = {}
    n_workers = max(1, os.cpu_count() or 4)
    print(f'Processing with {n_workers} workers...')

    with concurrent.futures.ProcessPoolExecutor(max_workers=n_workers) as pool:
        for result in tqdm(pool.map(_process_apk, jobs, chunksize=4),
                           total=len(jobs), desc='Signing'):
            if result is None:
                continue
            pkg, sig = result
            pkg_signatures.setdefault(pkg, []).append(sig)

    output_path = Path('app/src/main/assets/scan/benign_signatures.bin')
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total_sigs = sum(len(v) for v in pkg_signatures.values())
    print(f'\nPackages: {len(pkg_signatures)}  Signatures: {total_sigs}')
    print(f'Writing -> {output_path} ...')

    with open(output_path, 'wb') as f:
        f.write(struct.pack('<I', len(pkg_signatures)))
        for pkg in sorted(pkg_signatures):
            pkg_b = pkg.encode('utf-8', errors='ignore')
            f.write(struct.pack('<B', len(pkg_b)))
            f.write(pkg_b)
            sigs = pkg_signatures[pkg]
            f.write(struct.pack('<I', len(sigs)))
            for sig in sigs:
                f.write(struct.pack('<' + 'Q' * K_HASHES, *sig))

    size = output_path.stat().st_size
    print(f'Done: {output_path} = {size:,} bytes ({size / 1_048_576:.2f} MB)')


if __name__ == '__main__':
    main()
