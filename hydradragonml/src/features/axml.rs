//! Minimal parser for Android's binary XML (AXML) format, used to read
//! AndroidManifest.xml directly out of the APK zip without needing the
//! `aapt`/`aapt2` toolchain.
//!
//! Format reference: this binary chunk format is documented by AOSP in
//! frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h and has
//! been reverse engineered/described publicly many times (e.g.
//! "justanapplication.wordpress.com" AXML series). We implement just enough
//! of it to walk the XML tree and read attribute values.

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;

// Well-known android: attribute resource IDs (stable across AOSP versions,
// published in android/R.attr / frameworks/base res-ids).
const ATTR_NAME: u32 = 0x01010003; // android:name
const ATTR_MIN_SDK_VERSION: u32 = 0x0101020c; // android:minSdkVersion
const ATTR_TARGET_SDK_VERSION: u32 = 0x01010270; // android:targetSdkVersion

const TYPE_STRING: u8 = 0x03;

/// Dangerous-protection-level permissions as published by Android
/// (developer.android.com/guide/topics/permissions/overview#normal-dangerous,
/// and the android.Manifest.permission reference, protectionLevel="dangerous").
const DANGEROUS_PERMISSIONS: &[&str] = &[
    "READ_CALENDAR", "WRITE_CALENDAR",
    "CAMERA",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
    "ANSWER_PHONE_CALLS", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS",
    "BODY_SENSORS",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "ACCEPT_HANDOVER", "ACTIVITY_RECOGNITION",
];

#[derive(Debug, Default, Clone)]
pub struct ManifestFeatures {
    pub dangerous_permissions: u32,
    pub total_permissions: u32,
    pub activities: u32,
    pub services: u32,
    pub receivers: u32,
    pub min_sdk: u32,
    pub target_sdk: u32,
}

struct StringPool {
    strings: Vec<String>,
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn read_i32(b: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn parse_string_pool(b: &[u8], chunk_start: usize, chunk_size: usize) -> Option<StringPool> {
    let header_size = read_u16(b, chunk_start + 2)? as usize;
    let string_count = read_u32(b, chunk_start + 8)? as usize;
    let flags = read_u32(b, chunk_start + 16)?;
    let strings_start = read_u32(b, chunk_start + 20)? as usize;
    let is_utf8 = flags & 0x100 != 0;

    let mut strings = Vec::with_capacity(string_count);
    let offsets_off = chunk_start + header_size;
    for i in 0..string_count {
        let entry_off = offsets_off + i * 4;
        let str_off = chunk_start + strings_start + read_u32(b, entry_off)? as usize;
        if str_off >= chunk_start + chunk_size {
            strings.push(String::new());
            continue;
        }
        let s = if is_utf8 {
            // u8 length (or two bytes if >0x7f), then UTF-8 bytes, NUL terminated.
            let mut p = str_off;
            // skip UTF-16 length indicator byte(s) then UTF-8 length byte(s)
            let skip_len = |p: &mut usize| {
                let b0 = b[*p];
                *p += 1;
                if b0 & 0x80 != 0 {
                    *p += 1;
                }
            };
            skip_len(&mut p); // utf16 length (unused)
            let len_start = p;
            skip_len(&mut p);
            let byte_len = if b[len_start] & 0x80 != 0 {
                ((b[len_start] as usize & 0x7f) << 8) | b[len_start + 1] as usize
            } else {
                b[len_start] as usize
            };
            let start = p;
            String::from_utf8_lossy(b.get(start..start + byte_len)?).into_owned()
        } else {
            // u16 length, then UTF-16LE code units.
            let len = read_u16(b, str_off)? as usize;
            let start = str_off + 2;
            let mut units = Vec::with_capacity(len);
            for j in 0..len {
                units.push(read_u16(b, start + j * 2)?);
            }
            String::from_utf16_lossy(&units)
        };
        strings.push(s);
    }
    Some(StringPool { strings })
}

/// Walks the AXML chunk tree and extracts manifest-level features.
/// Returns `None` only if the buffer isn't a recognizable AXML document.
pub fn analyze_manifest(b: &[u8]) -> Option<ManifestFeatures> {
    if b.len() < 8 {
        return None;
    }
    let mut pool: Option<StringPool> = None;
    let mut resource_map: Vec<u32> = Vec::new();
    let mut feats = ManifestFeatures::default();
    let mut seen_any_element = false;

    // Track the currently open <uses-permission>/<permission> element so we
    // can read its android:name attribute value.
    #[derive(PartialEq)]
    enum Ctx {
        None,
        UsesPermission,
        UsesSdk,
    }

    // AXML files start with a RES_XML_TYPE container header (type 0x0003,
    // headerSize=8, chunkSize=whole file). It is not a walkable chunk itself;
    // the string pool / resource map / element chunks follow it. Without
    // skipping it the walk jumps straight past every element and we would
    // never see the manifest contents.
    let mut off = 0usize;
    if read_u16(b, 0)? == RES_XML_TYPE {
        let header_size = read_u16(b, 2)? as usize;
        if header_size < 8 || header_size > b.len() {
            return None;
        }
        off = header_size;
    }

    while off + 8 <= b.len() {
        let chunk_type = read_u16(b, off)?;
        let header_size = read_u16(b, off + 2)? as usize;
        let chunk_size = read_u32(b, off + 4)? as usize;
        if chunk_size < header_size || off + chunk_size > b.len() || chunk_size == 0 {
            break;
        }

        match chunk_type {
            RES_STRING_POOL_TYPE => {
                pool = parse_string_pool(b, off, chunk_size);
            }
            0x0180 /* RES_XML_RESOURCE_MAP_TYPE */ => {
                let mut p = off + header_size;
                while p + 4 <= off + chunk_size {
                    resource_map.push(read_u32(b, p)?);
                    p += 4;
                }
            }
            RES_XML_START_ELEMENT_TYPE => {
                seen_any_element = true;
                // node header (0x10 bytes after the 8-byte chunk header):
                // lineNumber, comment, then ns(i32), name(i32)
                let node_off = off + 8; // after type/header_size/size
                let ns_name_off = node_off + 8; // skip lineNumber(4)+comment(4)
                let name_idx = read_i32(b, ns_name_off + 4)?;
                let elem_name = pool
                    .as_ref()
                    .and_then(|p| p.strings.get(name_idx as usize))
                    .cloned()
                    .unwrap_or_default();

                let attr_start_off = ns_name_off + 8; // attributeStart(u16), attributeSize(u16), attributeCount(u16), ...
                let attribute_start = read_u16(b, attr_start_off)? as usize;
                let attribute_size = read_u16(b, attr_start_off + 2)? as usize;
                let attribute_count = read_u16(b, attr_start_off + 4)? as usize;
                // attributeStart is relative to the ResXMLTree_attrExt struct,
                // which begins 8 bytes into the node (after lineNumber/comment).
                // Reading it relative to `node_off` alone makes us start 8 bytes
                // too early and we would mis-read the ns/name fields (e.g. the
                // android namespace uri) as if they were attributes, zeroing
                // every permission value.
                let attrs_base = node_off + 8 + attribute_start;

                let mut ctx = Ctx::None;
                match elem_name.as_str() {
                    "activity" | "activity-alias" => feats.activities += 1,
                    "service" => feats.services += 1,
                    "receiver" => feats.receivers += 1,
                    "uses-permission" | "uses-permission-sdk-23" | "permission" => {
                        feats.total_permissions += 1;
                        ctx = Ctx::UsesPermission;
                    }
                    "uses-sdk" => ctx = Ctx::UsesSdk,
                    _ => {}
                }

                if ctx != Ctx::None {
                    for i in 0..attribute_count {
                        let a_off = attrs_base + i * attribute_size;
                        if a_off + 20 > b.len() {
                            break;
                        }
                        let attr_name_idx = read_i32(b, a_off + 4)?;
                        let raw_value_idx = read_i32(b, a_off + 8)?;
                        let data_type = *b.get(a_off + 15)?;
                        let data = read_u32(b, a_off + 16)?;

                        let attr_res_id = resource_map
                            .get(attr_name_idx.max(0) as usize)
                            .copied()
                            .unwrap_or(0);

                        match ctx {
                            Ctx::UsesPermission if attr_res_id == ATTR_NAME => {
                                let name = if data_type == TYPE_STRING && raw_value_idx >= 0 {
                                    pool.as_ref()
                                        .and_then(|p| p.strings.get(raw_value_idx as usize))
                                        .cloned()
                                        .unwrap_or_default()
                                } else {
                                    String::new()
                                };
                                let short = name.rsplit('.').next().unwrap_or(&name);
                                if DANGEROUS_PERMISSIONS.contains(&short) {
                                    feats.dangerous_permissions += 1;
                                }
                            }
                            Ctx::UsesSdk if attr_res_id == ATTR_MIN_SDK_VERSION => {
                                feats.min_sdk = data;
                            }
                            Ctx::UsesSdk if attr_res_id == ATTR_TARGET_SDK_VERSION => {
                                feats.target_sdk = data;
                            }
                            _ => {}
                        }
                    }
                }
            }
            RES_XML_END_ELEMENT_TYPE => {}
            _ => {}
        }

        off += chunk_size;
    }

    if !seen_any_element {
        return None;
    }
    Some(feats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(analyze_manifest(b"not axml").is_none());
    }
}
