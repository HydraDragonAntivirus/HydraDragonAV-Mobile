//! Low-level FFI bindings to the vendored libunrar C++ source.
//!
//! For the safe high-level API see the `unrar-ng` crate.
//!
//! ## Filename encoding cargo features
//!
//! This sys crate exposes a `linux-batch-extract-utf8` cargo feature
//! (default-on) that defines `UNRAR_NG_FORCE_UTF8` for the C build,
//! routing libunrar's `WideToChar` / `CharToWide` (in `unicode.cpp`)
//! through `WideToUtf` / `UtfToWide` (locale-independent UTF-8 transforms,
//! the same path macOS uses via the auto-defined `_APPLE` macro) on
//! non-Apple non-Windows Unix targets. With it disabled, libunrar uses
//! its upstream `wcsrtombs` / `mbsrtowcs` path which honors `LC_CTYPE`.
//!
//! See the high-level `unrar-ng` crate documentation for the full
//! design rationale, including the companion `linux-batch-extract-setlocale`
//! feature on the high-level crate that provides Rust-side
//! `OnceLock`-managed `setlocale(LC_CTYPE, "")` for callers who run with
//! `default-features = false` and want CLI-equivalent
//! locale-respecting behavior without writing setlocale code themselves.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

use libc::wchar_t;

#[cfg(feature = "std")]
use std::os::raw::{c_char, c_int, c_uchar, c_uint};

#[cfg(not(feature = "std"))]
use libc::{c_char, c_int, c_uchar, c_uint};

// ----------------- ENV SPECIFIC ----------------- //

#[cfg(windows)]
mod env {
    pub use {
        winapi::shared::minwindef::{LPARAM, UINT, UCHAR, INT},
        winapi::shared::ntdef::LONG,
    };
}


#[cfg(not(windows))]
mod env {
    use super::*;

    #[cfg(feature = "std")]
    use std::os::raw::c_long;

    #[cfg(not(feature = "std"))]
    use libc::c_long;

    pub type LPARAM = c_long;
    pub type LONG = c_long;
    pub type UINT = c_uint;
    pub type INT = c_int;
    pub type UCHAR = c_uchar;
}

pub use self::env::INT;
pub use self::env::LONG;
pub use self::env::LPARAM;
pub use self::env::UCHAR;
pub use self::env::UINT;

pub type WCHAR = wchar_t;

// ----------------- CONSTANTS ----------------- //

pub const ERAR_SUCCESS: c_int = 0;
pub const ERAR_END_ARCHIVE: c_int = 10;
pub const ERAR_NO_MEMORY: c_int = 11;
pub const ERAR_BAD_DATA: c_int = 12;
pub const ERAR_BAD_ARCHIVE: c_int = 13;
pub const ERAR_UNKNOWN_FORMAT: c_int = 14;
pub const ERAR_EOPEN: c_int = 15;
pub const ERAR_ECREATE: c_int = 16;
pub const ERAR_ECLOSE: c_int = 17;
pub const ERAR_EREAD: c_int = 18;
pub const ERAR_EWRITE: c_int = 19;
pub const ERAR_SMALL_BUF: c_int = 20;
pub const ERAR_UNKNOWN: c_int = 21;
pub const ERAR_MISSING_PASSWORD: c_int = 22;
pub const ERAR_EREFERENCE: c_int = 23;
pub const ERAR_BAD_PASSWORD: c_int = 24;
pub const ERAR_LARGE_DICT: c_int = 25;

pub const RAR_OM_LIST: c_uint = 0;
pub const RAR_OM_EXTRACT: c_uint = 1;
pub const RAR_OM_LIST_INCSPLIT: c_uint = 2;

pub const RAR_SKIP: c_int = 0;
pub const RAR_TEST: c_int = 1;
pub const RAR_EXTRACT: c_int = 2;

pub const RAR_VOL_ASK: LPARAM = 0;
pub const RAR_VOL_NOTIFY: LPARAM = 1;

pub const RAR_HASH_NONE: c_uint = 0;
pub const RAR_HASH_CRC32: c_uint = 1;
pub const RAR_HASH_BLAKE2: c_uint = 2;

pub const RHDF_SPLITBEFORE: c_uint = 1 << 0; // 1, 0x1
pub const RHDF_SPLITAFTER: c_uint = 1 << 1; // 2, 0x2
pub const RHDF_ENCRYPTED: c_uint = 1 << 2; // 4, 0x4
                                           // pub const RHDF_RESERVED: c_uint = 1 << 3; // 8, 0x8
pub const RHDF_SOLID: c_uint = 1 << 4; // 16, 0x10
pub const RHDF_DIRECTORY: c_uint = 1 << 5; // 32, 0x20

pub const UCM_CHANGEVOLUME: c_uint = 0;
pub const UCM_PROCESSDATA: c_uint = 1;
pub const UCM_NEEDPASSWORD: c_uint = 2;
pub const UCM_CHANGEVOLUMEW: c_uint = 3;
pub const UCM_NEEDPASSWORDW: c_uint = 4;
pub const UCM_LARGEDICT: c_uint = 5;

// Fork-only event ids. Match dll.hpp explicit `UCM_EXTRACTFILE = 100`.
// Do NOT renumber to be consecutive with upstream UCM_LARGEDICT(5);
// 6..99 are reserved for future upstream UCM_* additions.
pub const UCM_EXTRACTFILE: c_uint = 100; // File extraction started
pub const UCM_EXTRACTFILE_OK: c_uint = 101; // File extraction succeeded
pub const UCM_EXTRACTFILE_ERR: c_uint = 102; // File extraction failed

// Compile-time guard: explicit reservation must not be silently re-numbered.
// `assert!` with a custom message is stable in const context since Rust 1.65;
// MSRV 1.94 fully covers it.
const _: () = {
    assert!(
        UCM_EXTRACTFILE == 100,
        "UCM_EXTRACTFILE must stay 100; 6..99 reserved for upstream UCM_*"
    );
    assert!(UCM_EXTRACTFILE_OK == 101);
    assert!(UCM_EXTRACTFILE_ERR == 102);
};

// RAROpenArchiveDataEx::Flags
pub const ROADF_VOLUME: c_uint = 0x0001;
pub const ROADF_COMMENT: c_uint = 0x0002;
pub const ROADF_LOCK: c_uint = 0x0004;
pub const ROADF_SOLID: c_uint = 0x0008;
pub const ROADF_NEWNUMBERING: c_uint = 0x0010;
pub const ROADF_SIGNED: c_uint = 0x0020;
pub const ROADF_RECOVERY: c_uint = 0x0040;
pub const ROADF_ENCHEADERS: c_uint = 0x0080;
pub const ROADF_FIRSTVOLUME: c_uint = 0x0100;

// RAROpenArchiveDataEx::OpFlags
pub const ROADOF_KEEPBROKEN: c_uint = 0x0001;

pub type ChangeVolProc = extern "C" fn(*mut c_char, c_int) -> c_int;
pub type ProcessDataProc = extern "C" fn(*mut c_uchar, c_int) -> c_int;
pub type Callback = extern "C" fn(UINT, LPARAM, LPARAM, LPARAM) -> c_int;

#[repr(C)]
pub struct Handle { _private: [u8; 0] }

// ----------------- STRUCTS ----------------- //

// All DLL structs are packed(1) to match the C++ `#pragma pack(push, 1)` in
// `vendor/unrar/dll.hpp`. Without packed(1), natural alignment in `#[repr(C)]`
// inserts padding before pointer fields that does not exist on the C side,
// causing every field after the first pointer to sit at a different offset
// than the library expects. The current integration tests only read fields
// before the first pointer, which masked this ABI drift — but it was real.

#[repr(C, packed(1))]
pub struct HeaderData {
    pub archive_name: [c_char; 260],
    pub filename: [c_char; 260],
    pub flags: c_uint,
    pub pack_size: c_uint,
    pub unp_size: c_uint,
    pub host_os: c_uint,
    pub file_crc: c_uint,
    pub file_time: c_uint,
    pub unp_ver: c_uint,
    pub method: c_uint,
    pub file_attr: c_uint,
    pub comment_buffer: *mut c_char,
    pub comment_buffer_size: c_uint,
    pub comment_size: c_uint,
    pub comment_state: c_uint,
}

#[repr(C, packed(1))]
pub struct HeaderDataEx {
    pub archive_name: [c_char; 1024],
    pub archive_name_w: [wchar_t; 1024],
    pub filename: [c_char; 1024],
    pub filename_w: [wchar_t; 1024],
    pub flags: c_uint,
    pub pack_size: c_uint,
    pub pack_size_high: c_uint,
    pub unp_size: c_uint,
    pub unp_size_high: c_uint,
    pub host_os: c_uint,
    pub file_crc: c_uint,
    pub file_time: c_uint,
    pub unp_ver: c_uint,
    pub method: c_uint,
    pub file_attr: c_uint,
    pub comment_buffer: *mut c_char,
    pub comment_buffer_size: c_uint,
    pub comment_size: c_uint,
    pub comment_state: c_uint,
    pub dict_size: c_uint,
    pub hash_type: c_uint,
    pub hash: [c_char; 32],
    pub redir_type: c_uint,
    pub redir_name: *mut wchar_t,
    pub redir_name_size: c_uint,
    pub dir_target: c_uint,
    pub mtime_low: c_uint,
    pub mtime_high: c_uint,
    pub ctime_low: c_uint,
    pub ctime_high: c_uint,
    pub atime_low: c_uint,
    pub atime_high: c_uint,
    pub arc_name_ex: *mut wchar_t,
    pub arc_name_ex_size: c_uint,
    pub file_name_ex: *mut wchar_t,
    pub file_name_ex_size: c_uint,
    pub reserved: [c_uint; 982],
}

#[repr(C, packed(1))]
pub struct OpenArchiveData {
    pub archive_name: *const c_char,
    pub open_mode: c_uint,
    pub open_result: c_uint,
    pub comment_buffer: *mut c_char,
    pub comment_buffer_size: c_uint,
    pub comment_size: c_uint,
    pub comment_state: c_uint,
}

#[repr(C, packed(1))]
pub struct OpenArchiveDataEx {
    pub archive_name: *const c_char,
    pub archive_name_w: *const wchar_t,
    pub open_mode: c_uint,
    pub open_result: c_uint,
    pub comment_buffer: *mut c_char,
    pub comment_buffer_size: c_uint,
    pub comment_size: c_uint,
    pub comment_state: c_uint,
    pub flags: c_uint,
    pub callback: Option<Callback>,
    pub user_data: LPARAM,
    pub op_flags: c_uint,
    pub comment_buffer_w: *mut wchar_t,
    pub mark_of_the_web: *mut wchar_t,
    pub reserved: [c_uint; 23],
}

// ----------------- LAYOUT ASSERTIONS ----------------- //
//
// These compile-time assertions verify that our Rust struct definitions
// match the C++ packed layout from `vendor/unrar/dll.hpp` (which sits
// inside a `#pragma pack(push, 1)` block). If upstream extends a struct
// prefix or we accidentally drop `packed(1)`, the drift turns into a hard
// compile error instead of silent memory corruption at runtime.
//
// We only assert the 64-bit pointer-width case because that's the only
// target we actively build and test. `LPARAM` is 8 bytes on every 64-bit
// target, but `wchar_t` is platform-dependent (2 bytes on Windows MSVC,
// 4 bytes on Linux/macOS/BSD), so all `HeaderDataEx` offsets after the
// first `[wchar_t; 1024]` array are parameterized by `size_of::<wchar_t>()`.
// 32-bit targets still build, they just don't get layout verification.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::{offset_of, size_of};

    // `wchar_t` width: 2 on Windows (UTF-16), 4 on Linux/macOS/BSD (UCS-4).
    const W: usize = size_of::<wchar_t>();

    // HeaderDataEx — packed, pointer=8
    assert!(offset_of!(HeaderDataEx, archive_name) == 0);
    assert!(offset_of!(HeaderDataEx, archive_name_w) == 1024);
    assert!(offset_of!(HeaderDataEx, filename) == 1024 + 1024 * W);
    assert!(offset_of!(HeaderDataEx, filename_w) == 2048 + 1024 * W);
    assert!(offset_of!(HeaderDataEx, flags) == 2048 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, file_attr) == 2088 + 2048 * W);
    // First pointer — this is where `#[repr(C)]` would have inserted 4
    // bytes of padding; `packed(1)` must not.
    assert!(offset_of!(HeaderDataEx, comment_buffer) == 2092 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, comment_buffer_size) == 2100 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, hash) == 2120 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, redir_type) == 2152 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, redir_name) == 2156 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, mtime_low) == 2172 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, atime_high) == 2192 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, arc_name_ex) == 2196 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, file_name_ex_size) == 2216 + 2048 * W);
    assert!(offset_of!(HeaderDataEx, reserved) == 2220 + 2048 * W);
    assert!(size_of::<HeaderDataEx>() == 6148 + 2048 * W);

    // OpenArchiveDataEx — packed, pointer=8
    assert!(offset_of!(OpenArchiveDataEx, archive_name) == 0);
    assert!(offset_of!(OpenArchiveDataEx, archive_name_w) == 8);
    assert!(offset_of!(OpenArchiveDataEx, open_mode) == 16);
    assert!(offset_of!(OpenArchiveDataEx, open_result) == 20);
    assert!(offset_of!(OpenArchiveDataEx, comment_buffer) == 24);
    assert!(offset_of!(OpenArchiveDataEx, comment_buffer_size) == 32);
    assert!(offset_of!(OpenArchiveDataEx, flags) == 44);
    assert!(offset_of!(OpenArchiveDataEx, callback) == 48);
    assert!(offset_of!(OpenArchiveDataEx, user_data) == 56);
    assert!(offset_of!(OpenArchiveDataEx, op_flags) == 64);
    assert!(offset_of!(OpenArchiveDataEx, comment_buffer_w) == 68);
    assert!(offset_of!(OpenArchiveDataEx, mark_of_the_web) == 76);
    assert!(offset_of!(OpenArchiveDataEx, reserved) == 84);
    assert!(size_of::<OpenArchiveDataEx>() == 176);
};

// ----------------- BINDINGS ----------------- //

#[link(name = "unrar", kind = "static")]
#[cfg_attr(all(windows, target_env = "gnu"), link(name = "stdc++", kind = "static", modifiers = "-bundle"))]
#[cfg_attr(target_os = "macos", link(name = "c++"))]
#[cfg_attr(any(target_os = "freebsd", target_os = "openbsd"), link(name = "c++"))]
#[cfg_attr(any(target_os = "linux", target_os = "netbsd"), link(name = "stdc++"))]
unsafe extern "C" {
    pub fn RAROpenArchive(data: *const OpenArchiveData) -> *const Handle;

    pub fn RAROpenArchiveEx(data: *const OpenArchiveDataEx) -> *const Handle;

    pub fn RARCloseArchive(handle: *const Handle) -> c_int;

    pub fn RARReadHeader(handle: *const Handle, header_data: *const HeaderData) -> c_int;

    pub fn RARReadHeaderEx(handle: *const Handle, header_data: *const HeaderDataEx) -> c_int;

    pub fn RARProcessFile(
        handle: *const Handle,
        operation: c_int,
        dest_path: *const c_char,
        dest_name: *const c_char,
    ) -> c_int;

    pub fn RARProcessFileW(
        handle: *const Handle,
        operation: c_int,
        dest_path: *const wchar_t,
        dest_name: *const wchar_t,
    ) -> c_int;

    pub fn RARSetCallback(handle: *const Handle, callback: Option<Callback>, user_data: LPARAM);

    pub fn RARSetChangeVolProc(handle: *const Handle, change_vol_proc: Option<ChangeVolProc>);

    pub fn RARSetProcessDataProc(handle: *const Handle, process_data_proc: Option<ProcessDataProc>);

    pub fn RARSetPassword(handle: *const Handle, password: *const c_char);

    pub fn RARGetDllVersion() -> c_int;

    /// Batch extract all files to destination path.
    /// This function bypasses the per-file API overhead for better performance
    /// when extracting archives with many small files.
    pub fn RARExtractAll(
        handle: *const Handle,
        dest_path: *const c_char,
    ) -> c_int;

    /// Batch extract all files to destination path (wide char version).
    /// This function bypasses the per-file API overhead for better performance
    /// when extracting archives with many small files.
    pub fn RARExtractAllW(
        handle: *const Handle,
        dest_path: *const wchar_t,
    ) -> c_int;
}

// ----------------- MINIMAL ABSTRACTIONS ----------------- //

impl Default for HeaderData {
    fn default() -> Self {
        HeaderData {
            archive_name: [0; 260],
            filename: [0; 260],
            flags: 0,
            pack_size: 0,
            unp_size: 0,
            host_os: 0,
            file_crc: 0,
            file_time: 0,
            unp_ver: 0,
            method: 0,
            file_attr: 0,
            comment_buffer: std::ptr::null_mut(),
            comment_buffer_size: 0,
            comment_size: 0,
            comment_state: 0,
        }
    }
}

impl Default for HeaderDataEx {
    fn default() -> Self {
        HeaderDataEx {
            archive_name: [0; 1024],
            archive_name_w: [0; 1024],
            filename: [0; 1024],
            filename_w: [0; 1024],
            flags: 0,
            pack_size: 0,
            pack_size_high: 0,
            unp_size: 0,
            unp_size_high: 0,
            host_os: 0,
            file_crc: 0,
            file_time: 0,
            unp_ver: 0,
            method: 0,
            file_attr: 0,
            comment_buffer: std::ptr::null_mut(),
            comment_buffer_size: 0,
            comment_size: 0,
            comment_state: 0,
            dict_size: 0,
            hash_type: 0,
            hash: [0; 32],
            redir_type: 0,
            redir_name: std::ptr::null_mut(),
            redir_name_size: 0,
            dir_target: 0,
            mtime_low: 0,
            mtime_high: 0,
            ctime_low: 0,
            ctime_high: 0,
            atime_low: 0,
            atime_high: 0,
            arc_name_ex: std::ptr::null_mut(),
            arc_name_ex_size: 0,
            file_name_ex: std::ptr::null_mut(),
            file_name_ex_size: 0,
            reserved: [0; 982],
        }
    }
}

impl OpenArchiveData {
    pub fn new(archive: *const c_char, mode: c_uint) -> Self {
        Self::with_comment_buffer(archive, mode, std::ptr::null_mut(), 0)
    }

    pub fn with_comment_buffer(
        archive_name: *const c_char,
        open_mode: c_uint,
        buffer: *mut c_char,
        buffer_size: c_uint,
    ) -> Self {
        OpenArchiveData {
            archive_name: archive_name,
            open_mode: open_mode,
            comment_buffer: buffer,
            comment_buffer_size: buffer_size,
            // set by library:
            open_result: 0,
            comment_size: 0,
            comment_state: 0,
        }
    }
}

impl OpenArchiveDataEx {
    #[cfg(any(target_os = "linux", target_os = "netbsd"))]
    pub fn new(archive: *const c_char, mode: c_uint) -> Self {
        Self::new_internal(archive, std::ptr::null(), mode)
    }

    #[cfg(not(any(target_os = "linux", target_os = "netbsd")))]
    pub fn new(archive: *const wchar_t, mode: c_uint) -> Self {
        Self::new_internal(std::ptr::null(), archive, mode)
    }

    fn new_internal(
        archive_name: *const c_char,
        archive_name_w: *const wchar_t,
        mode: c_uint,
    ) -> Self {
        OpenArchiveDataEx {
            archive_name,
            archive_name_w,
            open_mode: mode,
            open_result: 0,
            comment_buffer: std::ptr::null_mut(),
            comment_buffer_size: 0,
            comment_size: 0,
            comment_state: 0,
            flags: 0,
            callback: None,
            user_data: 0,
            op_flags: 0,
            comment_buffer_w: std::ptr::null_mut(),
            mark_of_the_web: std::ptr::null_mut(),
            reserved: [0; 23],
        }
    }
}

// ----------------- TESTS ----------------- //

#[cfg(test)]
mod tests {
    #[test]
    fn test_version() {
        assert_eq!(unsafe { super::RARGetDllVersion() }, 9);
    }
}
