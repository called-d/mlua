use std::ffi::CStr;
use std::os::raw::{c_char, c_void, c_int};
use crate::{lua_CFunction, lua_State};

pub(crate) type lua_ModifyFunction = unsafe extern "C-unwind" fn(L: *mut lua_State);
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct StructDebugLibOption {
    pub deny_debug: u8,
    pub deny_getuservalue: u8,
    pub deny_gethook: u8,
    pub deny_getinfo: u8,
    pub deny_getlocal: u8,
    pub deny_getregistry: u8,
    pub deny_getmetatable: u8,
    pub deny_getupvalue: u8,
    pub deny_upvaluejoin: u8,
    pub deny_upvalueid: u8,
    pub deny_setuservalue: u8,
    pub deny_sethook: u8,
    pub deny_setlocal: u8,
    pub deny_setmetatable: u8,
    pub deny_setupvalue: u8,
    pub deny_traceback: u8,
    pub deny_setcstacklimit: u8,
}

#[derive(Debug, Default)]
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

#[cfg_attr(all(windows, raw_dylib), link(name = "lua54", kind = "raw-dylib"))]
unsafe extern "C-unwind" {
    pub fn set_loadfileroot(fileroot: *const c_char) -> *mut c_char;
    pub fn set_ioroot(fileroot: *const c_char) -> *mut c_char;
    pub fn deny_load_stdin() -> c_void;
    pub fn allow_load_stdin() -> c_void;
    pub fn deny_open_stdin() -> c_void;
    pub fn allow_open_stdin() -> c_void;
    pub fn deny_popen() -> c_void;
    pub fn allow_popen() -> c_void;
    pub fn deny_exit() -> c_void;
    pub fn allow_exit() -> c_void;
    pub fn deny_tmp() -> c_void;
    pub fn allow_tmp() -> c_void;
    pub fn deny_getenv() -> c_void;
    pub fn allow_getenv() -> c_void;
    pub fn set_getenv_prefix(prefix: *const c_char) -> *mut c_char;
    pub fn deny_setlocale() -> c_void;
    pub fn allow_setlocale() -> c_void;
    pub fn deny_collectgarbage() -> c_void;
    pub fn allow_collectgarbage() -> c_void;
    pub fn deny_require() -> c_void;
    pub fn allow_require() -> c_void;
    pub fn deny_loadlib() -> c_void;
    pub fn allow_loadlib() -> c_void;
    pub fn deny_searchpath() -> c_void;
    pub fn allow_searchpath() -> c_void;
    pub fn set_path_override(path_override: *const c_char) -> *mut c_char;
    pub fn set_cpath_override(cpath_override: *const c_char) -> *mut c_char;
    pub fn set_package_searchers_modifier_func(f: Option<lua_ModifyFunction>) -> Option<lua_ModifyFunction>;
    fn set_deny_debug_lib(deny_list: StructDebugLibOption) -> c_void;

    pub fn deny_time() -> c_void;
    pub fn allow_time() -> c_void;
    pub fn set_rep_max(max: usize) -> c_void;
    pub fn reset_rep_max() -> c_void;
    pub fn set_clock_precision(p: c_int) -> c_void;
    pub fn set_clock_overwrite(f: Option<lua_CFunction>) -> Option<lua_CFunction>;
    // pub fn deny_binary_io() -> c_void;
    // pub fn allow_binary_io() -> c_void;
    pub fn set_read_extension_allowlist(list: *const c_char) -> *mut c_char;
    pub fn set_write_extension_allowlist(list: *const c_char) -> *mut c_char;
}

pub fn set_debug_lib_option(deny_list: DebugLibOption) {
    unsafe {
        set_deny_debug_lib(StructDebugLibOption {
            deny_debug: if deny_list.deny_debug { 1 } else { 0 },
            deny_getuservalue: if deny_list.deny_getuservalue { 1 } else { 0 },
            deny_gethook: if deny_list.deny_gethook { 1 } else { 0 },
            deny_getinfo: if deny_list.deny_getinfo { 1 } else { 0 },
            deny_getlocal: if deny_list.deny_getlocal { 1 } else { 0 },
            deny_getregistry: if deny_list.deny_getregistry { 1 } else { 0 },
            deny_getmetatable: if deny_list.deny_getmetatable { 1 } else { 0 },
            deny_getupvalue: if deny_list.deny_getupvalue { 1 } else { 0 },
            deny_upvaluejoin: if deny_list.deny_upvaluejoin { 1 } else { 0 },
            deny_upvalueid: if deny_list.deny_upvalueid { 1 } else { 0 },
            deny_setuservalue: if deny_list.deny_setuservalue { 1 } else { 0 },
            deny_sethook: if deny_list.deny_sethook { 1 } else { 0 },
            deny_setlocal: if deny_list.deny_setlocal { 1 } else { 0 },
            deny_setmetatable: if deny_list.deny_setmetatable { 1 } else { 0 },
            deny_setupvalue: if deny_list.deny_setupvalue { 1 } else { 0 },
            deny_traceback: if deny_list.deny_traceback { 1 } else { 0 },
            deny_setcstacklimit: if deny_list.deny_setcstacklimit { 1 } else { 0 },
        });
    }
}

#[unsafe(no_mangle)] pub extern "C" fn is_in_dir (rootdir: *const c_char, f: *const c_char) -> c_int {
    use std::path::{Path, absolute};
    let rootdir = absolute(Path::new(unsafe{CStr::from_ptr(rootdir)}.to_string_lossy().as_ref()));
    let fname = absolute(Path::new(unsafe{CStr::from_ptr(f)}.to_string_lossy().as_ref()));
    let Ok(rootdir) = rootdir else { return 0 };
    let Ok(fname) = fname else { return 0 };
    if fname.starts_with(rootdir) { 1 } else { 0 }
}
