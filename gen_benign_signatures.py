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
    """Robust binary AndroidManifest.xml (AXML) package name parser in pure Python."""
    try:
        if len(data) < 8 or struct.unpack("<H", data[0:2])[0] != 0x0003:
            return None
        # String pool starts at offset 8
        header_type, header_size = struct.unpack("<HH", data[8:12])
        if header_type != 0x0001:
            return None
        string_count, style_count, flags, string_start, style_start = struct.unpack("<IIIII", data[12:32])
        
        # Read string offsets
        offsets = []
        for i in range(string_count):
            offsets.append(struct.unpack("<I", data[32 + i*4 : 36 + i*4])[0])
            
        # Read strings
        strings = []
        pool_data = data[8 + string_start : 8 + header_size]
        is_utf8 = (flags & (1 << 8)) != 0
        
        for offset in pool_data[:0]: # dummy to make linter happy
            pass

        for offset in offsets:
            if is_utf8:
                u8len = pool_data[offset]
                if u8len & 0x80:
                    u8len = ((u8len & 0x7F) << 8) | pool_data[offset + 1]
                    offset += 2
                else:
                    offset += 1
                strings.append(pool_data[offset : offset + u8len].decode('utf-8', errors='ignore'))
            else:
                u16len = struct.unpack("<H", pool_data[offset:offset+2])[0]
                if u16len & 0x8000:
                    u16len = ((u16len & 0x7FFF) << 16) | struct.unpack("<H", pool_data[offset+2:offset+4])[0]
                    offset += 4
                else:
                    offset += 2
                strings.append(pool_data[offset : offset + u16len*2].decode('utf-16le', errors='ignore'))
                
        # Find manifest tag
        off = 8 + header_size
        while off + 8 <= len(data):
            ctype, csize = struct.unpack("<HI", data[off:off+6])
            if csize == 0:
                break
            if ctype == 0x0102: # RES_XML_START_ELEMENT
                name_idx = struct.unpack("<I", data[off+20:off+24])[0]
                if name_idx < len(strings) and strings[name_idx] == "manifest":
                    attr_start, attr_count = struct.unpack("<HH", data[off+24:off+28])
                    abase = off + 16 + attr_start
                    for i in range(min(attr_count, 256)):
                        a = abase + i * 20
                        aname = struct.unpack("<I", data[a+4:a+8])[0]
                        if aname < len(strings) and strings[aname] == "package":
                            raw = struct.unpack("<I", data[a+8:a+12])[0]
                            if raw != 0xFFFFFFFF:
                                return strings[raw]
                            else:
                                val_idx = struct.unpack("<I", data[a+16:a+20])[0]
                                if val_idx < len(strings):
                                    return strings[val_idx]
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
