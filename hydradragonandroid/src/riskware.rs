use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) static TESTKEY_DETECTION_ENABLED: AtomicBool = AtomicBool::new(false);

const KNOWN_TESTKEY_SHA1: &[&str] = &[
    "61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81",
    "E128AD41BA48B993EA696F801C36C7C41E1A9C6C",
    "A9FE368A91C9EAB8187722C1C97FD35C959ED03E",
    "3B1C59C13173A4A4C0E896AF3DF999568145D2FA",
];

pub(crate) fn check_testkey(cert_sha1: &str) -> bool {
    let upper = cert_sha1.to_uppercase();
    KNOWN_TESTKEY_SHA1.iter().any(|k| *k == upper)
}

pub(crate) fn set_testkey_detection_enabled(enabled: bool) {
    TESTKEY_DETECTION_ENABLED.store(enabled, Ordering::Relaxed);
}

pub(crate) fn is_testkey_detection_enabled() -> bool {
    TESTKEY_DETECTION_ENABLED.load(Ordering::Relaxed)
}
