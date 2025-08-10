use std::os::raw::{c_char, c_int};
use std::{fmt, ptr};
use ffi::{lua_CFunction, lua_State};
pub use ffi::jail::DebugLibOption;

pub fn jail(options: JailOptions) {
    use ffi::jail;

    unsafe {
        free_cstr(jail::set_loadfileroot(options.loadfile_root.map_or(ptr::null(), |root|path_to_ptr(root))));
        free_cstr(jail::set_ioroot(options.io_root.map_or(ptr::null(), |root|path_to_ptr(root))));
        if options.deny_load_stdin { jail::deny_load_stdin() } else { jail::allow_load_stdin() };
        if options.deny_open_stdin { jail::deny_open_stdin() } else { jail::allow_open_stdin() };
        if options.deny_popen { jail::deny_popen() } else { jail::allow_popen() };
        if options.deny_exit { jail::deny_exit() } else { jail::allow_exit() };
        if options.deny_exit { jail::deny_tmp() } else { jail::allow_tmp() };
        if options.deny_tmp { jail::deny_tmp() } else { jail::allow_tmp() };
        let getenv_prefix = match options.getenv {
            GetEnvOption::Prefix(prefix) => {
                jail::allow_getenv();
                Some(prefix)
            },
            GetEnvOption::AllowAll => {
                jail::allow_getenv();
                None
            }
            GetEnvOption::DenyAll => {
                jail::deny_getenv();
                None
            },
        };
        free_cstr(jail::set_getenv_prefix(getenv_prefix.map_or(ptr::null(), |prefix|std::ffi::CString::new(prefix).unwrap().into_raw())));
        if options.deny_setlocale { jail::deny_setlocale() } else { jail::allow_setlocale() };
        if options.deny_collectgarbage { jail::deny_collectgarbage() } else { jail::allow_collectgarbage() };
        if options.package_lib.deny_require { jail::deny_require() } else { jail::allow_require() };
        if options.package_lib.deny_loadlib { jail::deny_loadlib() } else { jail::allow_loadlib() };
        if options.package_lib.deny_searchpath { jail::deny_searchpath() } else { jail::allow_searchpath() };
        free_cstr(jail::set_path_override(options.package_lib.path_override.map_or(ptr::null(), |s|std::ffi::CString::new(s).unwrap().into_raw())));
        free_cstr(jail::set_cpath_override(options.package_lib.cpath_override.map_or(ptr::null(), |s|std::ffi::CString::new(s).unwrap().into_raw())));
        jail::set_package_searchers_modifier_func(options.package_lib.modify_searchers);
        match options.rep_max_len {
            Some(max) => jail::set_rep_max(max),
            None => jail::reset_rep_max(),
        };
        if options.deny_time { jail::deny_time() } else { jail::allow_time() };
        jail::set_clock_precision(0);
        jail::set_clock_overwrite(match options.os_clock {
            OsClockOption::Allow => None,
            OsClockOption::DownPrecision(p) => {
                jail::set_clock_precision(p);
                None
            }
            OsClockOption::Deny => Some(deny_clock),
            OsClockOption::Overwrite(f) => Some(f),
        });
        jail::set_debug_lib_option(options.debug_lib);
        // if options.deny_binary_io { jail::deny_binary_io() } else { jail::allow_binary_io() };
        free_cstr(jail::set_read_extension_allowlist(options.read_extension_allowlist.map_or(ptr::null(), |list|std::ffi::CString::new(build_list(list)).unwrap().into_raw())));
        free_cstr(jail::set_write_extension_allowlist(options.write_extension_allowlist.map_or(ptr::null(), |list|std::ffi::CString::new(build_list(list)).unwrap().into_raw())));
    }
}
#[derive(Debug, Default)]
pub enum GetEnvOption {
    #[default] AllowAll,
    Prefix(String),
    DenyAll,
}

type lua_ModifyFunction = unsafe extern "C-unwind" fn(L: *mut lua_State);

#[derive(Default)]
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
    ///     mlua::jail::jail(JailOptions {
    ///         package_lib: PackageLibOption {
    ///             modify_searchers: Some(drop_all_searchers),
    ///             ..Default::default()
    ///         },
    ///         ..Default::default()
    ///     });
    ///
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

#[derive(Debug, Default)]
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

#[derive(Debug, Default)]
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
    pub os_clock: OsClockOption,
    pub debug_lib: DebugLibOption,
    // pub deny_binary_io: bool,
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
            os_clock: OsClockOption::Deny,
            debug_lib: DebugLibOption::deny_all(),
            // deny_binary_io: true,
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

fn free_cstr(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    let _ = unsafe { std::ffi::CString::from_raw(ptr) };
}
fn path_to_ptr(path: std::path::PathBuf) -> *const c_char {
    use std::ffi::CString;
    if let Some(path) = path.to_str() {
        if let Ok(path) = CString::new(path) {
            return path.into_raw()
        }
    }
    // is_in_dir("", path) always returns false
    CString::new("").unwrap().into_raw()
}
fn build_list(list: Vec<String>) -> String { format!(",{},",  list.join(",").to_ascii_lowercase()) }