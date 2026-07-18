import os
import re
import sys
import struct
import zipfile
import numpy as np
from pathlib import Path

# We can import harvest_strings, _token_fast, and MAX_TOKENS from train_model
sys.path.insert(0, str(Path(__file__).parent))
import train_model as tm

MIN_STR_LEN = tm.MIN_STR_LEN
MAX_TOKENS = tm.MAX_TOKENS
MAX_ENTRY_SCAN = tm.MAX_ENTRY_SCAN
FNV_PRIME = tm.FNV_PRIME

# MinHash configuration: 64 hash functions
K_HASHES = 64

def hash_token_i(t: int, i: int) -> int:
    # Match the Rust equivalent: t.wrapping_xor(i).wrapping_mul(FNV_PRIME)
    return ((t ^ i) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF

def get_minhash_signature(tokens: set) -> list:
    sig = [0xFFFFFFFFFFFFFFFF] * K_HASHES
    # Sort or iterate over tokens to ensure deterministic order (though set iteration works since we compute min)
    for t in tokens:
        for i in range(K_HASHES):
            val = hash_token_i(t, i)
            if val < sig[i]:
                sig[i] = val
    return sig

def get_axml_package_name(data: bytes) -> str:
    """Parse binary AndroidManifest.xml (AXML) and return the package name.

    Matches the Rust axml_package / axml_strings logic exactly:
      - ResXMLTree      : type=0x0003 at offset 0
      - ResStringPool   : type=0x0001 at offset 8
        - [8 ] type     u16
        - [10] hdrSize  u16   (28 bytes normally)
        - [12] poolSize u32   (total chunk, skip this many bytes for next chunk)
        - [16] strCount u32
        - [20] styCount u32
        - [24] flags    u32   (bit 8 = UTF-8 flag)
        - [28] strStart u32   (offset into pool where strings begin)
        - [32] styStart u32
        - [36...] offsets table (strCount x u32)
      - String data begins at pool_base + strStart (where pool_base = 8)
      - XML events start at pool_base + poolSize
      - RES_XML_START_ELEMENT = 0x0102:
        - [off+20] name (u32): element name index
        - [off+24] attributeStart (u16)
        - [off+26] attributeSize  (u16)  ← 20 bytes normally
        - [off+28] attributeCount (u16)
        Attributes base = off + 16 + attributeStart, each 20 bytes:
          [a+4]  name index (u32)
          [a+8]  rawValue   (u32): string pool idx, or 0xFFFFFFFF if typed
          [a+16] data       (u32): used when rawValue == 0xFFFFFFFF
    """
    def u16(d, o):
        return struct.unpack_from("<H", d, o)[0]

    def u32(d, o):
        return struct.unpack_from("<I", d, o)[0]

    try:
        if len(data) < 36 or u16(data, 0) != 0x0003:
            return None

        # String pool chunk starts at offset 8
        POOL = 8
        if u16(data, POOL) != 0x0001:
            return None
        pool_hdr_size = u16(data, POOL + 2)   # usually 28
        pool_size     = u32(data, POOL + 4)   # total chunk size
        str_count     = u32(data, POOL + 8)
        flags         = u32(data, POOL + 16)
        str_start     = u32(data, POOL + 20)  # offset within chunk to string data
        is_utf8       = bool(flags & (1 << 8))

        # Offset table: immediately after the pool header
        offsets_base = POOL + pool_hdr_size
        # String data base (absolute)
        str_data_base = POOL + str_start

        def read_string(tbl_idx: int) -> str:
            if tbl_idx >= str_count:
                return ''
            rel = u32(data, offsets_base + tbl_idx * 4)
            p = str_data_base + rel
            if is_utf8:
                # UTF-16 char count (may be 2 bytes)
                n = data[p]; p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[p]; p += 1
                # UTF-8 byte count (may be 2 bytes)
                n = data[p]; p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[p]; p += 1
                return data[p:p + n].decode('utf-8', errors='ignore')
            else:
                n = u16(data, p); p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | u16(data, p); p += 2
                return data[p:p + n * 2].decode('utf-16-le', errors='ignore')

        # Walk XML events — they start right after the string pool chunk
        off = POOL + pool_size
        guard = 0
        while off + 8 <= len(data) and guard < 100_000:
            guard += 1
            ctype = u16(data, off)
            csize = u32(data, off + 4)
            if csize == 0:
                break
            if ctype == 0x0102:  # RES_XML_START_ELEMENT
                name_idx    = u32(data, off + 20)
                attr_start  = u16(data, off + 24)
                attr_count  = u16(data, off + 28)   # ← attributeCount, NOT attributeSize
                if read_string(name_idx) == 'manifest':
                    abase = off + 16 + attr_start
                    for i in range(min(attr_count, 256)):
                        a = abase + i * 20
                        if a + 20 > len(data):
                            break
                        aname = u32(data, a + 4)
                        if read_string(aname) == 'package':
                            raw = u32(data, a + 8)
                            idx = raw if raw != 0xFFFF_FFFF else u32(data, a + 16)
                            return read_string(idx) or None
            off += csize
    except Exception:
        pass
    return None


def extract_tokens(apk_path: str):
    """Clone of train_model.py features extraction logic returning the raw token set."""
    try:
        z = zipfile.ZipFile(apk_path, 'r')
        namelist = z.namelist()
    except Exception:
        return None, None

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

    if not tokens or not manifest_data:
        return None, None

    package_name = get_axml_package_name(manifest_data)
    return package_name, tokens

def main():
    dataset_root = Path("dataset/benign")
    if not dataset_root.exists():
        print(f"ERROR: {dataset_root} does not exist.")
        sys.exit(1)

    print("Scanning benign APKs and generating MinHash signatures...")
    pkg_signatures = {}
    
    apk_count = 0
    for root, _, files in os.walk(dataset_root):
        for fname in files:
            if not fname.lower().endswith('.apk'):
                continue
            apk_path = Path(root) / fname
            
            pkg, tokens = extract_tokens(str(apk_path))
            if not pkg or not tokens:
                continue
                
            sig = get_minhash_signature(tokens)
            pkg_signatures.setdefault(pkg, []).append(sig)
            
            apk_count += 1
            if apk_count % 100 == 0:
                print(f"  Processed {apk_count} APKs...")

    output_path = Path("app/src/main/assets/scan/benign_signatures.bin")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\nWriting {len(pkg_signatures)} packages ({apk_count} signatures) to {output_path}...")
    with open(output_path, "wb") as f:
        # 1. Write total packages count (u32)
        f.write(struct.pack("<I", len(pkg_signatures)))
        for pkg, sigs in sorted(pkg_signatures.items()):
            pkg_bytes = pkg.encode("utf-8", errors="ignore")
            # 2. Write package name length (u8)
            f.write(struct.pack("<B", len(pkg_bytes)))
            # 3. Write package name bytes
            f.write(pkg_bytes)
            # 4. Write total signatures count for this package (u32)
            f.write(struct.pack("<I", len(sigs)))
            for sig in sigs:
                # 5. Write 64 u64 MinHash values
                for val in sig:
                    f.write(struct.pack("<Q", val))

    print("Successfully built benign signatures database!")

if __name__ == "__main__":
    main()
