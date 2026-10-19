use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar};
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

#[cfg_attr(all(windows, raw_dylib), link(name = "lua54", kind = "raw-dylib"))]
unsafe extern "C-unwind" {
    /// Copies `opt` into the state (null clears). Returns non-zero on failure.
    pub fn lua_setjail(L: *mut lua_State, opt: *const JailOption, size: usize) -> c_int;
    /// Never null. All zero if not jailed.
    pub fn lua_getjail(L: *mut lua_State) -> *const JailOption;
}

/// Called from jail.c
#[unsafe(no_mangle)] pub extern "C" fn is_in_dir (rootdir: *const c_char, f: *const c_char) -> c_int {
    let rootdir = normalize(unsafe{CStr::from_ptr(rootdir)}.to_string_lossy().as_ref());
    let fname = normalize(unsafe{CStr::from_ptr(f)}.to_string_lossy().as_ref());
    let Some(rootdir) = rootdir else { return 0 };
    let Some(fname) = fname else { return 0 };
    if fname.starts_with(rootdir) { 1 } else { 0 }
}

/// Absolute path with `.` and `..` resolved lexically.
/// `std::path::absolute` keeps `..` on Unix, so `root/../x` would start with `root`.
fn normalize(path: &str) -> Option<std::path::PathBuf> {
    use std::path::{Component, PathBuf};
    if path.is_empty() { return None }
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
