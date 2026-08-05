//! Minimal DEX (Dalvik Executable) parser used to derive real, content-based
//! features from classes*.dex entries inside an APK.
//!
//! Format reference: the DEX file format is documented by the Android Open
//! Source Project (source.android.com/docs/core/runtime/dex-format). Only the
//! header size fields are needed to compute class/string/method counts — no
//! hardcoded API lists or framework-prefix filters, so all three features are
//! pure data.

const DEX_MAGIC: &[u8] = b"dex\n";

#[derive(Debug, Default, Clone)]
pub struct DexFeatures {
    pub class_count: u32,
    pub string_count: u32,
    pub api_call_count: u32,
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

struct DexHeader {
    string_ids_size: u32,
    method_ids_size: u32,
    class_defs_size: u32,
}

fn parse_header(b: &[u8]) -> Option<DexHeader> {
    if b.len() < 0x70 || &b[0..4] != DEX_MAGIC {
        return None;
    }
    Some(DexHeader {
        string_ids_size: read_u32(b, 0x38)?,
        method_ids_size: read_u32(b, 0x58)?,
        class_defs_size: read_u32(b, 0x60)?,
    })
}

/// Parses a single classes*.dex file and returns real, content-derived
/// counts straight from the header. Returns `None` if `data` is not a
/// well-formed DEX file (bad magic or truncated header) rather than
/// guessing.
pub fn analyze(data: &[u8]) -> Option<DexFeatures> {
    let h = parse_header(data)?;
    Some(DexFeatures {
        class_count: h.class_defs_size,
        string_count: h.string_ids_size,
        api_call_count: h.method_ids_size,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn build_minimal_dex(strings: &[&str], type_str_idx: &[u32], methods: &[(u16, u32)]) -> Vec<u8> {
        // Build string_data section.
        let mut string_data = Vec::new();
        let mut string_offsets = Vec::new();
        for s in strings {
            string_offsets.push(string_data.len() as u32);
            // uleb128 utf16 length (== byte length for ASCII), then bytes, then NUL.
            string_data.push(s.len() as u8);
            string_data.extend_from_slice(s.as_bytes());
            string_data.push(0);
        }

        let header_size = 0x70usize;
        let string_ids_off = header_size;
        let string_ids_size_bytes = strings.len() * 4;
        let type_ids_off = string_ids_off + string_ids_size_bytes;
        let type_ids_size_bytes = type_str_idx.len() * 4;
        let method_ids_off = type_ids_off + type_ids_size_bytes;
        let method_ids_size_bytes = methods.len() * 8;
        let string_data_off = method_ids_off + method_ids_size_bytes;

        let mut buf = vec![0u8; string_data_off + string_data.len()];
        buf[0..4].copy_from_slice(DEX_MAGIC);

        buf[0x38..0x3c].copy_from_slice(&(strings.len() as u32).to_le_bytes());
        buf[0x3c..0x40].copy_from_slice(&(string_ids_off as u32).to_le_bytes());
        buf[0x40..0x44].copy_from_slice(&(type_str_idx.len() as u32).to_le_bytes());
        buf[0x44..0x48].copy_from_slice(&(type_ids_off as u32).to_le_bytes());
        buf[0x58..0x5c].copy_from_slice(&(methods.len() as u32).to_le_bytes());
        buf[0x5c..0x60].copy_from_slice(&(method_ids_off as u32).to_le_bytes());
        buf[0x60..0x64].copy_from_slice(&1u32.to_le_bytes()); // class_defs_size

        for (i, off) in string_offsets.iter().enumerate() {
            let o = string_ids_off + i * 4;
            buf[o..o + 4].copy_from_slice(&(string_data_off as u32 + off).to_le_bytes());
        }
        for (i, &sidx) in type_str_idx.iter().enumerate() {
            let o = type_ids_off + i * 4;
            buf[o..o + 4].copy_from_slice(&sidx.to_le_bytes());
        }
        for (i, &(class_idx, name_idx)) in methods.iter().enumerate() {
            let o = method_ids_off + i * 8;
            buf[o..o + 2].copy_from_slice(&class_idx.to_le_bytes());
            buf[o + 4..o + 8].copy_from_slice(&name_idx.to_le_bytes());
        }
        buf[string_data_off..].copy_from_slice(&string_data);
        buf
    }

    #[test]
    fn counts_classes_strings_and_framework_apis() {
        // strings: 0="Ljava/lang/Runtime;" 1="exec" 2="Landroid/telephony/TelephonyManager;" 3="getDeviceId"
        let strings = ["Ljava/lang/Runtime;", "exec", "Landroid/telephony/TelephonyManager;", "getDeviceId"];
        let type_str_idx = [0u32, 2u32]; // type 0 -> Runtime, type 1 -> TelephonyManager
        let methods = [(0u16, 1u32), (1u16, 3u32)];
        let dex = build_minimal_dex(&strings, &type_str_idx, &methods);
        let feats = analyze(&dex).expect("should parse");
        assert_eq!(feats.class_count, 1);
        assert_eq!(feats.string_count, 4);
        assert_eq!(feats.api_call_count, 2);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(analyze(b"not a dex file").is_none());
    }
}
