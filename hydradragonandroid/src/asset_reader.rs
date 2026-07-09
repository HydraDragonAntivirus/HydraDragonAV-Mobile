use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, Ordering};

static AASSET_MANAGER: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

#[link(name = "android")]
unsafe extern "C" {
    fn AAssetManager_fromJava(
        env: *mut std::ffi::c_void,
        asset_manager: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn AAssetManager_open(
        mgr: *mut std::ffi::c_void,
        filename: *const std::os::raw::c_char,
        mode: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    fn AAssetManager_openDir(
        mgr: *mut std::ffi::c_void,
        dirname: *const std::os::raw::c_char,
    ) -> *mut std::ffi::c_void;
    fn AAsset_getLength(asset: *mut std::ffi::c_void) -> usize;
    fn AAsset_read(
        asset: *mut std::ffi::c_void,
        buf: *mut std::ffi::c_void,
        count: usize,
    ) -> std::os::raw::c_int;
    fn AAsset_close(asset: *mut std::ffi::c_void);
    fn AAssetDir_getNextFileName(dir: *mut std::ffi::c_void) -> *const std::os::raw::c_char;
    fn AAssetDir_close(dir: *mut std::ffi::c_void);
}

/// Convert a Java AssetManager jobject to a native AAssetManager pointer
/// using `AAssetManager_fromJava`. Call once, then pass the pointer to [`init`].
pub fn from_java(
    env: *mut std::ffi::c_void,
    asset_manager: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    unsafe { AAssetManager_fromJava(env, asset_manager) }
}

const AASSET_MODE_BUFFER: std::os::raw::c_int = 3;

pub fn init(mgr: *mut std::ffi::c_void) {
    AASSET_MANAGER.store(mgr, Ordering::Relaxed);
}

pub fn read_file_bytes(relative_path: &str) -> Option<Vec<u8>> {
    let mgr = AASSET_MANAGER.load(Ordering::Relaxed);
    if mgr.is_null() {
        return None;
    }
    unsafe {
        let c_path = std::ffi::CString::new(relative_path).ok()?;
        let asset = AAssetManager_open(mgr, c_path.as_ptr(), AASSET_MODE_BUFFER);
        if asset.is_null() {
            return None;
        }
        let len = AAsset_getLength(asset);
        let mut buf = vec![0u8; len];
        let read = AAsset_read(asset, buf.as_mut_ptr() as *mut std::ffi::c_void, len);
        AAsset_close(asset);
        if read < 0 {
            return None;
        }
        if (read as usize) < len {
            buf.truncate(read as usize);
        }
        Some(buf)
    }
}

pub fn list_assets(asset_dir: &str) -> Option<Vec<String>> {
    let mgr = AASSET_MANAGER.load(Ordering::Relaxed);
    if mgr.is_null() {
        return None;
    }
    unsafe {
        let c_path = std::ffi::CString::new(asset_dir).ok()?;
        let dir = AAssetManager_openDir(mgr, c_path.as_ptr());
        if dir.is_null() {
            return None;
        }
        let mut names = Vec::new();
        loop {
            let c_name = AAssetDir_getNextFileName(dir);
            if c_name.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr(c_name).to_string_lossy().into_owned();
            if !name.is_empty() {
                names.push(name);
            }
        }
        AAssetDir_close(dir);
        Some(names)
    }
}

pub fn read_all_assets(asset_dir: &str) -> HashMap<String, Vec<u8>> {
    let mut files = HashMap::new();
    let names = match list_assets(asset_dir) {
        Some(n) => n,
        None => return files,
    };
    for name in names {
        let path = format!("{}/{}", asset_dir, name);
        if let Some(bytes) = read_file_bytes(&path) {
            files.insert(name, bytes);
        }
    }
    files
}