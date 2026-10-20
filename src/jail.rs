//! Per-state sandbox options. Pass [`JailOptions`] to [`LuaOptions::jail`].
//!
//! [`LuaOptions::jail`]: crate::LuaOptions::jail
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::{fmt, ptr};
use ffi::{lua_CFunction, lua_State};
pub use ffi::jail::DebugLibOption;

use crate::error::{Error, Result};

/// Sets `options` to the state. The strings are copied by the C side.
///
/// Must be called before opening the libraries, since `package.path`, `package.searchers`
/// and `io.stdin` are set up when the library is opened.
pub(crate) unsafe fn apply(state: *mut lua_State, options: &JailOptions) -> Result<()> {
    let loadfile_root = options.loadfile_root.as_ref().map(path_to_cstring);
    let io_root = options.io_root.as_ref().map(path_to_cstring);
    let read_extension_allowlist = options.read_extension_allowlist.as_ref().map(build_list).transpose()?;
    let write_extension_allowlist = options.write_extension_allowlist.as_ref().map(build_list).transpose()?;
    let (deny_getenv, getenv_prefix) = match &options.getenv {
        GetEnvOption::AllowAll => (false, None),
        GetEnvOption::Prefix(prefix) => (false, Some(cstring(prefix)?)),
        GetEnvOption::DenyAll => (true, None),
    };
    let path_override = options.package_lib.path_override.as_deref().map(cstring).transpose()?;
    let cpath_override = options.package_lib.cpath_override.as_deref().map(cstring).transpose()?;
    let (clock_precision, clock_overwrite) = match options.os_clock {
        OsClockOption::Allow => (0, None),
        OsClockOption::DownPrecision(p) => (p, None),
        OsClockOption::Deny => (0, Some(deny_clock as lua_CFunction)),
        OsClockOption::Overwrite(f) => (0, Some(f)),
    };

    let opt = ffi::jail::JailOption {
        loadfile_root: as_ptr(&loadfile_root),
        ioroot: as_ptr(&io_root),
        read_extension_allowlist: as_ptr(&read_extension_allowlist),
        write_extension_allowlist: as_ptr(&write_extension_allowlist),
        getenv_prefix: as_ptr(&getenv_prefix),
        path_override: as_ptr(&path_override),
        cpath_override: as_ptr(&cpath_override),
        package_searchers_modifier: options.package_lib.modify_searchers,
        clock_overwrite,
        rep_max: options.rep_max_len.unwrap_or(0),
        rep_max_limited: options.rep_max_len.is_some() as c_int,
        clock_precision,
        deny_load_stdin: options.deny_load_stdin as u8,
        deny_open_stdin: options.deny_open_stdin as u8,
        deny_popen: options.deny_popen as u8,
        deny_exit: options.deny_exit as u8,
        deny_tmp: options.deny_tmp as u8,
        deny_getenv: deny_getenv as u8,
        deny_setlocale: options.deny_setlocale as u8,
        deny_collectgarbage: options.deny_collectgarbage as u8,
        deny_require: options.package_lib.deny_require as u8,
        deny_loadlib: options.package_lib.deny_loadlib as u8,
        deny_searchpath: options.package_lib.deny_searchpath as u8,
        deny_time: options.deny_time as u8,
        deny_binary_chunk: options.deny_binary_chunk as u8,
        debug_option: (&options.debug_lib).into(),
    };
    if ffi::jail::lua_setjail(state, &opt, size_of::<ffi::jail::JailOption>()) != 0 {
        return Err(Error::MemoryError("cannot set jail options".to_string()));
    }
    Ok(())
}

/// Whether the state refuses binary chunks ([`JailOptions::deny_binary_chunk`]).
pub(crate) unsafe fn denies_binary_chunk(state: *mut lua_State) -> bool {
    (*ffi::jail::lua_getjail(state)).deny_binary_chunk != 0
}

#[derive(Debug, Default, Clone)]
pub enum GetEnvOption {
    #[default] AllowAll,
    Prefix(String),
    DenyAll,
}

type lua_ModifyFunction = unsafe extern "C-unwind" fn(L: *mut lua_State);

#[derive(Default, Clone)]
pub struct PackageLibOption {
    pub deny_require: bool,
    pub deny_loadlib: bool,
    pub deny_searchpath: bool,
    pub path_override: Option<String>,
    pub cpath_override: Option<String>,
    /// Escape hatch for modifying the `package.searchers` table.
    ///
    /// # Example
    /// ```
    /// use std::os::raw::{c_char, c_int};
    /// use mlua::{Lua, LuaOptions, StdLib};
    /// use mlua::jail::{JailOptions, PackageLibOption};
    /// use mlua::ffi::lua_State;
    ///
    /// unsafe extern "C-unwind" fn empty_loader(L: *mut lua_State) -> c_int {
    ///     const MESSAGE: &[u8] = b"\n\tcan't load module\0";
    ///     ffi::lua_pushstring(L, MESSAGE.as_ptr() as *const c_char);
    ///     ffi::lua_pushnil(L);
    ///     return 2;
    /// }
    /// unsafe extern "C-unwind" fn drop_all_searchers(L: *mut lua_State) {
    ///     // package.searchers = { empty_loader, empty_loader, empty_loader, empty_loader }
    ///     let len = ffi::lua_rawlen(L, -1);
    ///     for i in 1..=len {
    ///         ffi::lua_pushcfunction(L, empty_loader);
    ///         ffi::lua_rawseti(L, -2, i.try_into().unwrap());
    ///     }
    /// }
    ///
    /// let lua = Lua::new_with(StdLib::ALL_SAFE, LuaOptions::new().jail(JailOptions {
    ///     package_lib: PackageLibOption {
    ///         modify_searchers: Some(drop_all_searchers),
    ///         ..Default::default()
    ///     },
    ///     ..Default::default()
    /// }));
    /// ```
    pub modify_searchers: Option<lua_ModifyFunction>,
}
impl PackageLibOption {
    pub fn deny_all() -> Self {
        Self {
            deny_require: true,
            deny_loadlib: true,
            deny_searchpath: true,
            path_override: Some("".to_string()),
            cpath_override: Some("".to_string()),
            modify_searchers: Some(drop_all_searchers),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub enum OsClockOption {
    #[default] Allow,
    /// limit precision of os.clock()
    ///
    /// `floor(clock*pow(10,6-p))/pow(10,6-p)`
    ///
    /// # Example
    /// `DownPrecision(3)` -> msec
    ///
    /// `DownPrecision(6)` -> sec
    DownPrecision(c_int),
    /// overwrite return of os.clock()
    ///
    /// `f(clock)`
    Overwrite(lua_CFunction),
    Deny,
}

unsafe extern "C-unwind" fn empty_loader(L: *mut lua_State) -> c_int {
    const MESSAGE: &[u8] = b"\n\tcan't load module\0";
    ffi::lua_pushstring(L, MESSAGE.as_ptr() as *const c_char);
    ffi::lua_pushnil(L);
    return 2;
}
unsafe extern "C-unwind" fn drop_all_searchers(L: *mut lua_State) {
    let len = ffi::lua_rawlen(L, -1);
    for i in 1..=len {
        ffi::lua_pushcfunction(L, empty_loader);
        ffi::lua_rawseti(L, -2, i.try_into().unwrap());
    }
}

unsafe extern "C-unwind" fn deny_clock(L: *mut lua_State) -> c_int {
    ffi::lua_pushnil(L);
    return 1;
}

#[derive(Debug, Default, Clone)]
pub struct JailOptions {
    pub loadfile_root: Option<std::path::PathBuf>,
    pub io_root: Option<std::path::PathBuf>,
    pub deny_load_stdin: bool,
    pub deny_open_stdin: bool,
    pub deny_popen: bool,
    pub deny_exit: bool,
    pub deny_tmp: bool,
    pub getenv: GetEnvOption,
    pub deny_setlocale: bool,
    pub deny_collectgarbage: bool,
    pub package_lib: PackageLibOption,
    pub rep_max_len: Option<usize>,
    pub deny_time: bool,
    /// Denies loading precompiled chunks with `load` / `loadfile` / `dofile` / `require`
    /// (and [`Lua::load`] from Rust). `string.dump` is still allowed.
    ///
    /// [`Lua::load`]: crate::Lua::load
    pub deny_binary_chunk: bool,
    pub os_clock: OsClockOption,
    pub debug_lib: DebugLibOption,
    pub read_extension_allowlist: Option<Vec<String>>,
    pub write_extension_allowlist: Option<Vec<String>>,
}
impl JailOptions {
    pub fn deny_all() -> Self {
        Self {
            loadfile_root: Some(std::path::PathBuf::from("")),
            io_root: Some(std::path::PathBuf::from("")),
            deny_load_stdin: true,
            deny_open_stdin: true,
            deny_popen: true,
            deny_exit: true,
            deny_tmp: true,
            getenv: GetEnvOption::DenyAll,
            deny_setlocale: true,
            deny_collectgarbage: true,
            package_lib: PackageLibOption::deny_all(),
            rep_max_len: Some(1024),
            deny_time: true,
            deny_binary_chunk: true,
            os_clock: OsClockOption::Deny,
            debug_lib: DebugLibOption::deny_all(),
            read_extension_allowlist: Some(vec![]),
            write_extension_allowlist: Some(vec![]),
        }
    }
}

impl fmt::Debug for PackageLibOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PackageLibOption")
            .field("deny_require", &self.deny_require)
            .field("deny_loadlib", &self.deny_loadlib)
            .field("deny_searchpath", &self.deny_searchpath)
            .field("path_override", &self.path_override)
            .field("cpath_override", &self.cpath_override)
            .field("modify_searchers", &format_args!(
                "{}",
                if self.modify_searchers.is_some() {
                    "Some(<closure>)"
                } else {
                    "None"
                }
            ))
            .finish()
    }
}

fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| Error::RuntimeError(format!("invalid jail option: {e}")))
}
fn as_ptr(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(ptr::null(), |s| s.as_ptr())
}
fn path_to_cstring(path: &std::path::PathBuf) -> CString {
    if let Some(path) = path.to_str() {
        if let Ok(path) = CString::new(path) {
            return path
        }
    }
    // is_in_dir("", path) always returns false
    CString::default()
}
fn build_list(list: &Vec<String>) -> Result<CString> {
    cstring(&format!(",{},", list.join(",").to_ascii_lowercase()))
}
