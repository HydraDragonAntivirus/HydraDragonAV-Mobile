import sys
import zipfile

def main():
    if len(sys.argv) != 2:
        print("Kullanim: python debug_zip_stats.py <apk_yolu>")
        sys.exit(1)

    apk_path = sys.argv[1]
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            namelist = z.namelist()
            total_entries = len(namelist)
            unique_names = len(set(n.lower() for n in namelist))

            scan_attempted = 0
            scan_ok = 0
            scan_failed = 0
            for name in namelist:
                lname = name.lower()
                should_scan = (lname == 'androidmanifest.xml' or lname == 'resources.arsc'
                               or lname.endswith('.dex') or lname.startswith('meta-inf/'))
                if not should_scan:
                    continue
                scan_attempted += 1
                try:
                    info = z.getinfo(name)
                    if info.file_size > 16 * 1024 * 1024:
                        data = z.read(name)[:16 * 1024 * 1024]
                    else:
                        data = z.read(name)
                    scan_ok += 1
                    print(f"  ENTRY: {name}  declared_size={info.file_size}  compress_size={info.compress_size}  actual_read_len={len(data)}")
                except Exception as e:
                    scan_failed += 1
                    print(f"  FAILED: {name} -> {e}")

            print(f"total_entries={total_entries}")
            print(f"unique_names={unique_names}")
            print(f"scan_attempted={scan_attempted} scan_ok={scan_ok} scan_failed={scan_failed}")
    except Exception as e:
        print(f"ZIP ACILAMADI: {e}")

if __name__ == "__main__":
    main()
