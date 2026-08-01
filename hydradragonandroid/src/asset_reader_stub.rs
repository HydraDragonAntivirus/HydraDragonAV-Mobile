/// No-op stubs for host builds (non-Android) so cargo test / the repro
/// example compile without the AAssetManager NDK FFI. Zero-copy asset loading
/// only exists on device; host builds fall back to the pre-read `files` map.

/// Mirrors the Android `AssetBuffer` (kept unit-type-free so host callers that
/// only ever see `None` compile unchanged).
pub struct AssetBuffer {
    pub asset: *mut std::ffi::c_void,
    pub ptr: *const u8,
    pub len: usize,
}

pub fn open_asset_buffer(_relative_path: &str) -> Option<AssetBuffer> {
    None
}
