use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar};
use std::path::{Component, Path, PathBuf};
use crate::{lua_CFunction, lua_State};

pub type lua_ModifyFunction = unsafe extern "C-unwind" fn(L: *mut lua_State);

/// `DebugLibJailOption` in jail.h
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct DebugLibJailOption {
    pub deny_debug: c_uchar,
    pub deny_getuservalue: c_uchar,
    pub deny_gethook: c_uchar,
    pub deny_getinfo: c_uchar,
    pub deny_getlocal: c_uchar,
    pub deny_getregistry: c_uchar,
    pub deny_getmetatable: c_uchar,
    pub deny_getupvalue: c_uchar,
    pub deny_upvaluejoin: c_uchar,
    pub deny_upvalueid: c_uchar,
    pub deny_setuservalue: c_uchar,
    pub deny_sethook: c_uchar,
    pub deny_setlocal: c_uchar,
    pub deny_setmetatable: c_uchar,
    pub deny_setupvalue: c_uchar,
    pub deny_traceback: c_uchar,
    pub deny_setcstacklimit: c_uchar,
}

/// `JailOption` in jail.h. Strings are copied by `lua_setjail`.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct JailOption {
    pub loadfile_root: *const c_char,
    pub ioroot: *const c_char,
    pub read_extension_allowlist: *const c_char,
    pub write_extension_allowlist: *const c_char,
    pub getenv_prefix: *const c_char,
    pub path_override: *const c_char,
    pub cpath_override: *const c_char,
    pub package_searchers_modifier: Option<lua_ModifyFunction>,
    pub clock_overwrite: Option<lua_CFunction>,
    pub rep_max: usize,
    pub rep_max_limited: c_int,
    pub clock_precision: c_int,
    pub deny_load_stdin: c_uchar,
    pub deny_open_stdin: c_uchar,
    pub deny_popen: c_uchar,
    pub deny_exit: c_uchar,
    pub deny_tmp: c_uchar,
    pub deny_getenv: c_uchar,
    pub deny_setlocale: c_uchar,
    pub deny_collectgarbage: c_uchar,
    pub deny_require: c_uchar,
    pub deny_loadlib: c_uchar,
    pub deny_searchpath: c_uchar,
    pub deny_time: c_uchar,
    pub deny_binary_chunk: c_uchar,
    pub debug_option: DebugLibJailOption,
}

#[derive(Debug, Default, Clone)]
pub struct DebugLibOption {
    pub deny_debug: bool,
    pub deny_getuservalue: bool,
    pub deny_gethook: bool,
    pub deny_getinfo: bool,
    pub deny_getlocal: bool,
    pub deny_getregistry: bool,
    pub deny_getmetatable: bool,
    pub deny_getupvalue: bool,
    pub deny_upvaluejoin: bool,
    pub deny_upvalueid: bool,
    pub deny_setuservalue: bool,
    pub deny_sethook: bool,
    pub deny_setlocal: bool,
    pub deny_setmetatable: bool,
    pub deny_setupvalue: bool,
    pub deny_traceback: bool,
    pub deny_setcstacklimit: bool,
}
impl DebugLibOption {
    pub fn deny_all() -> Self {
        Self {
            deny_debug: true,
            deny_getuservalue: true,
            deny_gethook: true,
            deny_getinfo: true,
            deny_getlocal: true,
            deny_getregistry: true,
            deny_getmetatable: true,
            deny_getupvalue: true,
            deny_upvaluejoin: true,
            deny_upvalueid: true,
            deny_setuservalue: true,
            deny_sethook: true,
            deny_setlocal: true,
            deny_setmetatable: true,
            deny_setupvalue: true,
            deny_traceback: true,
            deny_setcstacklimit: true,
        }
    }
}
impl From<&DebugLibOption> for DebugLibJailOption {
    fn from(o: &DebugLibOption) -> Self {
        Self {
            deny_debug: o.deny_debug as c_uchar,
            deny_getuservalue: o.deny_getuservalue as c_uchar,
            deny_gethook: o.deny_gethook as c_uchar,
            deny_getinfo: o.deny_getinfo as c_uchar,
            deny_getlocal: o.deny_getlocal as c_uchar,
            deny_getregistry: o.deny_getregistry as c_uchar,
            deny_getmetatable: o.deny_getmetatable as c_uchar,
            deny_getupvalue: o.deny_getupvalue as c_uchar,
            deny_upvaluejoin: o.deny_upvaluejoin as c_uchar,
            deny_upvalueid: o.deny_upvalueid as c_uchar,
            deny_setuservalue: o.deny_setuservalue as c_uchar,
            deny_sethook: o.deny_sethook as c_uchar,
            deny_setlocal: o.deny_setlocal as c_uchar,
            deny_setmetatable: o.deny_setmetatable as c_uchar,
            deny_setupvalue: o.deny_setupvalue as c_uchar,
            deny_traceback: o.deny_traceback as c_uchar,
            deny_setcstacklimit: o.deny_setcstacklimit as c_uchar,
        }
    }
}

// jail is only available with the vendored Lua (lua-src), so no raw-dylib linking here
unsafe extern "C-unwind" {
    /// Copies `opt` into the state (null clears). Returns non-zero on failure.
    pub fn lua_setjail(L: *mut lua_State, opt: *const JailOption, size: usize) -> c_int;
    /// Never null. All zero if not jailed.
    pub fn lua_getjail(L: *mut lua_State) -> *const JailOption;
}

/// Called from jail.c. `rootdir` is UTF-8 (from [`JailOption`]), `f` is a name passed to `fopen`.
#[unsafe(no_mangle)] pub extern "C" fn is_in_dir (rootdir: *const c_char, f: *const c_char) -> c_int {
    let Ok(rootdir) = unsafe{CStr::from_ptr(rootdir)}.to_str() else { return 0 };
    let Some(fname) = fopen_path(unsafe{CStr::from_ptr(f)}) else { return 0 };
    contains(Path::new(rootdir), &fname) as c_int
}

/// Called from jail.c. The directory of `os.tmpname`.
#[unsafe(no_mangle)] pub extern "C" fn is_in_tmp_dir (f: *const c_char) -> c_int {
    let Some(fname) = fopen_path(unsafe{CStr::from_ptr(f)}) else { return 0 };
    #[cfg(windows)] let tmp = std::env::temp_dir();
    #[cfg(not(windows))] let tmp = PathBuf::from("/tmp");
    contains(&tmp, &fname) as c_int
}

/// Both lexically (`..`, and device names on Windows) and with links resolved.
fn contains(root: &Path, f: &Path) -> bool {
    let (Some(root_n), Some(f_n)) = (normalize(root), normalize(f)) else { return false };
    if !f_n.starts_with(root_n) { return false }
    let (Ok(root_r), Some(f_r)) = (std::fs::canonicalize(root), resolve(f)) else { return false };
    f_r.starts_with(root_r)
}

/// Absolute path with `.` and `..` resolved lexically.
/// `std::path::absolute` keeps `..` on Unix, so `root/../x` would start with `root`.
fn normalize(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() { return None }
    let mut out = PathBuf::new();
    for c in std::path::absolute(path).ok()?.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => { out.pop(); }
            c => out.push(c),
        }
    }
    Some(out)
}

/// The file `fopen` would reach: links (and 8.3 names on Windows) resolved.
/// Only the last component may be missing (a file to be created), and it must not be a link.
fn resolve(path: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::fs::canonicalize(path) { return Some(p) }
    // a dangling link would be followed by "w"
    if std::fs::symlink_metadata(path).is_ok() { return None }
    let name = path.file_name()?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Some(std::fs::canonicalize(parent).ok()?.join(name))
}

/// The file name as `fopen` decodes it.
#[cfg(unix)]
fn fopen_path(s: &CStr) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(s.to_bytes())))
}

/// The file name as `fopen` decodes it: UTF-8 if the C locale is UTF-8, otherwise the code page
/// of the Win32 A functions (as UCRT does). A lead byte of CP932 etc. can take a following `\`.
#[cfg(windows)]
fn fopen_path(s: &CStr) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    const CP_ACP: u32 = 0;
    const CP_OEMCP: u32 = 1;
    const CP_UTF8: u32 = 65001;
    const MB_ERR_INVALID_CHARS: u32 = 0x8;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AreFileApisANSI() -> i32;
        fn MultiByteToWideChar(cp: u32, flags: u32, s: *const c_char, n: i32, w: *mut u16, wn: i32) -> i32;
    }
    unsafe extern "C" {
        /// code page of the current C locale (UCRT, msvcrt)
        fn ___lc_codepage_func() -> u32;
    }
    let n = i32::try_from(s.to_bytes().len()).ok()?;
    if n == 0 { return None }
    let cp = unsafe {
        if ___lc_codepage_func() == CP_UTF8 { CP_UTF8 }
        else if AreFileApisANSI() != 0 { CP_ACP }
        else { CP_OEMCP }
    };
    // invalid sequences: fopen fails or decodes them differently, so refuse
    let len = unsafe { MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, s.as_ptr(), n, std::ptr::null_mut(), 0) };
    if len <= 0 { return None }
    let mut wide = vec![0u16; len as usize];
    let len = unsafe { MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, s.as_ptr(), n, wide.as_mut_ptr(), len) };
    if len <= 0 { return None }
    wide.truncate(len as usize);
    Some(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
}

#[cfg(not(any(unix, windows)))]
fn fopen_path(s: &CStr) -> Option<PathBuf> {
    s.to_str().ok().map(PathBuf::from)
}
