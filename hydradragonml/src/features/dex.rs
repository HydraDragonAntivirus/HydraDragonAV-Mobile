//! Minimal DEX (Dalvik Executable) parser used to derive real, content-based
//! features from classes*.dex entries inside an APK.
//!
//! Format reference: the DEX file format is documented by the Android Open
//! Source Project (source.android.com/docs/core/runtime/dex-format). We only
//! need the header, string_ids, type_ids, method_ids and class_defs sections
//! to compute class/string/API counts, so we do not need a full disassembler.

const DEX_MAGIC: &[u8] = b"dex\n";

#[derive(Debug, Default, Clone)]
pub struct DexFeatures {
    pub class_count: u32,
    pub string_count: u32,
    pub api_call_count: u32,
    /// "high" severity findings: use of APIs that are commonly abused by
    /// malware but also have legitimate uses (dynamic code loading,
    /// reflection, telephony/SMS APIs, crypto APIs used for ransomware-style
    /// file encryption, native library loading of non-standard libs, etc).
    pub finding_high: u32,
    /// "critical" severity findings: a smaller set of APIs that are almost
    /// exclusively seen in malicious samples (runtime shell execution,
    /// installing/uninstalling packages programmatically, disabling
    /// Play Protect / admin receivers, premium SMS sending).
    pub finding_critical: u32,
}

/// Known API method signatures (class + method) associated with malicious
/// behavior in published Android malware research (Arp et al., "DREBIN:
/// Effective and Explainable Detection of Android Malware in Your Pocket",
/// NDSS 2014; and the API-usage feature sets used by MaMaDroid/Drebin-style
/// classifiers). These are widely documented framework APIs, not exploit
/// code.
const CRITICAL_APIS: &[(&str, &str)] = &[
    ("Ljava/lang/Runtime;", "exec"),
    ("Ljava/lang/ProcessBuilder;", "start"),
    ("Landroid/telephony/SmsManager;", "sendTextMessage"),
    ("Landroid/telephony/SmsManager;", "sendMultipartTextMessage"),
    ("Landroid/content/pm/PackageInstaller;", "commit"),
    ("Landroid/app/admin/DevicePolicyManager;", "setApplicationHidden"),
    ("Landroid/app/admin/DevicePolicyManager;", "lockNow"),
    ("Ldalvik/system/DexClassLoader;", "<init>"),
    ("Ldalvik/system/PathClassLoader;", "<init>"),
];

const HIGH_APIS: &[(&str, &str)] = &[
    ("Ljava/lang/reflect/Method;", "invoke"),
    ("Ljava/lang/Class;", "forName"),
    ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
    ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
    ("Landroid/telephony/TelephonyManager;", "getLine1Number"),
    ("Landroid/location/LocationManager;", "getLastKnownLocation"),
    ("Landroid/content/ContentResolver;", "query"),
    ("Ljavax/crypto/Cipher;", "doFinal"),
    ("Ljava/io/File;", "delete"),
    ("Landroid/content/pm/PackageManager;", "setComponentEnabledSetting"),
    ("Ljava/lang/System;", "loadLibrary"),
    ("Landroid/webkit/WebView;", "addJavascriptInterface"),
];

/// Any method whose defining class descriptor starts with one of these
/// prefixes is counted toward `api_call_count` (a call into the Android
/// framework or standard Java runtime, as opposed to app-defined code).
const FRAMEWORK_PREFIXES: &[&str] = &["Landroid/", "Ljava/", "Ldalvik/", "Ljavax/"];

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Reads a ULEB128-encoded value starting at `off`, returning (value, next_offset).
fn read_uleb128(b: &[u8], mut off: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let byte = *b.get(off)?;
        off += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    Some((result, off))
}

/// Reads the MUTF-8 string stored at a `string_data_off`: a ULEB128 utf16
/// length prefix followed by modified-UTF-8 bytes terminated by NUL. For our
/// purposes (class/method descriptors and names, which are ASCII in the
/// overwhelming majority of real DEX files) treating the bytes as UTF-8 is
/// sufficient.
fn read_dex_string(b: &[u8], data_off: usize) -> Option<String> {
    let (_utf16_len, str_start) = read_uleb128(b, data_off)?;
    let mut end = str_start;
    while *b.get(end)? != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&b[str_start..end]).into_owned())
}

struct DexHeader {
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
}

fn parse_header(b: &[u8]) -> Option<DexHeader> {
    if b.len() < 0x70 || &b[0..4] != DEX_MAGIC {
        return None;
    }
    Some(DexHeader {
        string_ids_size: read_u32(b, 0x38)?,
        string_ids_off: read_u32(b, 0x3c)?,
        type_ids_size: read_u32(b, 0x40)?,
        type_ids_off: read_u32(b, 0x44)?,
        method_ids_size: read_u32(b, 0x58)?,
        method_ids_off: read_u32(b, 0x5c)?,
        class_defs_size: read_u32(b, 0x60)?,
    })
}

/// Parses a single classes*.dex file and returns real, content-derived
/// counts. Returns `None` if `data` is not a well-formed DEX file (bad
/// magic or truncated header) rather than guessing.
pub fn analyze(data: &[u8]) -> Option<DexFeatures> {
    let h = parse_header(data)?;

    // string_ids: table of u32 offsets into the string data section.
    let mut strings: Vec<String> = Vec::with_capacity(h.string_ids_size as usize);
    for i in 0..h.string_ids_size {
        let entry_off = h.string_ids_off as usize + (i as usize) * 4;
        let data_off = read_u32(data, entry_off)? as usize;
        strings.push(read_dex_string(data, data_off).unwrap_or_default());
    }

    // type_ids: table of u32 indices into `strings`, giving type descriptors
    // like "Landroid/telephony/SmsManager;".
    let mut type_descriptors: Vec<String> = Vec::with_capacity(h.type_ids_size as usize);
    for i in 0..h.type_ids_size {
        let entry_off = h.type_ids_off as usize + (i as usize) * 4;
        let str_idx = read_u32(data, entry_off)? as usize;
        type_descriptors.push(strings.get(str_idx).cloned().unwrap_or_default());
    }

    // method_ids: each entry is { type_idx: u16 (class), proto_idx: u16,
    // name_idx: u32 }. class_idx indexes into type_ids, name_idx into
    // string_ids.
    let mut api_call_count = 0u32;
    let mut finding_high = 0u32;
    let mut finding_critical = 0u32;
    for i in 0..h.method_ids_size {
        let entry_off = h.method_ids_off as usize + (i as usize) * 8;
        let class_idx = u16::from_le_bytes(data.get(entry_off..entry_off + 2)?.try_into().ok()?) as usize;
        let name_idx = read_u32(data, entry_off + 4)? as usize;
        let class_desc = type_descriptors.get(class_idx).map(String::as_str).unwrap_or("");
        let method_name = strings.get(name_idx).map(String::as_str).unwrap_or("");

        if FRAMEWORK_PREFIXES.iter().any(|p| class_desc.starts_with(p)) {
            api_call_count += 1;
        }
        if CRITICAL_APIS.iter().any(|(c, m)| *c == class_desc && *m == method_name) {
            finding_critical += 1;
        } else if HIGH_APIS.iter().any(|(c, m)| *c == class_desc && *m == method_name) {
            finding_high += 1;
        }
    }

    Some(DexFeatures {
        class_count: h.class_defs_size,
        string_count: h.string_ids_size,
        api_call_count,
        finding_high,
        finding_critical,
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
    fn detects_critical_and_high_apis() {
        // strings: 0="Ljava/lang/Runtime;" 1="exec" 2="Landroid/telephony/TelephonyManager;" 3="getDeviceId"
        let strings = ["Ljava/lang/Runtime;", "exec", "Landroid/telephony/TelephonyManager;", "getDeviceId"];
        let type_str_idx = [0u32, 2u32]; // type 0 -> Runtime, type 1 -> TelephonyManager
        let methods = [(0u16, 1u32), (1u16, 3u32)];
        let dex = build_minimal_dex(&strings, &type_str_idx, &methods);
        let feats = analyze(&dex).expect("should parse");
        assert_eq!(feats.class_count, 1);
        assert_eq!(feats.string_count, 4);
        assert_eq!(feats.api_call_count, 2);
        assert_eq!(feats.finding_critical, 1);
        assert_eq!(feats.finding_high, 1);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(analyze(b"not a dex file").is_none());
    }
}
