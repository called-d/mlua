#![cfg(all(any(feature = "lua54", feature = "lua55"), feature = "vendored"))]

use std::path::PathBuf;

use mlua::jail::{GetEnvOption, JailOptions, PackageLibOption};
use mlua::{Lua, LuaOptions, Result, StdLib};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mlua-jail-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn jailed(options: JailOptions) -> Lua {
    Lua::new_with(StdLib::ALL_SAFE, LuaOptions::new().jail(options)).unwrap()
}

fn can_open(lua: &Lua, path: &std::path::Path) -> Result<bool> {
    lua.load("return io.open(...) ~= nil")
        .call(path.to_str().unwrap())
}

#[test]
fn test_jail_is_per_state() -> Result<()> {
    let a = temp_dir("a");
    let b = temp_dir("b");
    std::fs::write(a.join("x.txt"), "a").unwrap();
    std::fs::write(b.join("x.txt"), "b").unwrap();

    let lua_a = jailed(JailOptions {
        io_root: Some(a.clone()),
        deny_tmp: true,
        ..Default::default()
    });
    let lua_b = jailed(JailOptions {
        io_root: Some(b.clone()),
        deny_tmp: true,
        getenv: GetEnvOption::DenyAll,
        ..Default::default()
    });
    let free = Lua::new();

    assert!(can_open(&lua_a, &a.join("x.txt"))?);
    assert!(!can_open(&lua_a, &b.join("x.txt"))?);
    assert!(can_open(&lua_b, &b.join("x.txt"))?);
    assert!(!can_open(&lua_b, &a.join("x.txt"))?);
    assert!(can_open(&free, &a.join("x.txt"))?);
    assert!(can_open(&free, &b.join("x.txt"))?);

    // dropping one state must not affect the others
    drop(lua_b);
    assert!(can_open(&lua_a, &a.join("x.txt"))?);
    assert!(!can_open(&lua_a, &b.join("x.txt"))?);

    let path_env: Option<String> = free.load("return os.getenv('PATH')").eval()?;
    assert!(path_env.is_some());
    Ok(())
}

#[test]
fn test_jail_parent_dir() -> Result<()> {
    let root = temp_dir("parent").join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.parent().unwrap().join("secret.txt"), "s").unwrap();

    let lua = jailed(JailOptions {
        io_root: Some(root.clone()),
        deny_tmp: true,
        ..Default::default()
    });
    assert!(!can_open(&lua, &root.join("..").join("secret.txt"))?);
    Ok(())
}

#[test]
fn test_jail_package_path() -> Result<()> {
    let lua = jailed(JailOptions {
        package_lib: PackageLibOption {
            path_override: Some("jailed/?.lua".to_string()),
            ..Default::default()
        },
        ..Default::default()
    });
    let path: String = lua.load("return package.path").eval()?;
    assert_eq!(path, "jailed/?.lua");

    let path: String = Lua::new().load("return package.path").eval()?;
    assert_ne!(path, "jailed/?.lua");
    Ok(())
}

#[test]
fn test_jail_rep_max() -> Result<()> {
    let lua = jailed(JailOptions {
        rep_max_len: Some(10),
        ..Default::default()
    });
    let s: String = lua.load("return string.rep('ab', 5)").eval()?;
    assert_eq!(s, "ababababab");
    assert!(lua.load("return string.rep('ab', 6)").exec().is_err());
    assert!(lua.load("return string.rep('a', 4, ',')").exec().is_ok());
    assert!(lua.load("return string.rep('a', 6, ',')").exec().is_err());
    // string.packsize is not limited
    let size: usize = lua.load("return string.packsize('i16')").eval()?;
    assert_eq!(size, 16);
    Ok(())
}

#[test]
fn test_jail_threads() {
    // states created concurrently keep their own settings
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                let path = format!("t{i}/?.lua");
                for _ in 0..50 {
                    let lua = jailed(JailOptions {
                        package_lib: PackageLibOption {
                            path_override: Some(path.clone()),
                            ..Default::default()
                        },
                        ..Default::default()
                    });
                    let p: String = lua.load("return package.path").eval().unwrap();
                    assert_eq!(p, path);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_jail_binary_chunk() -> Result<()> {
    let dir = temp_dir("binary");
    let file = dir.join("f.luac");
    let free = Lua::new();
    let bytecode: mlua::LuaString = free.load("return string.dump(function() return 42 end)").eval()?;
    std::fs::write(&file, bytecode.as_bytes()).unwrap();

    let lua = jailed(JailOptions {
        deny_binary_chunk: true,
        ..Default::default()
    });
    lua.globals().set("bytecode", lua.create_string(bytecode.as_bytes())?)?;
    lua.globals().set("file", file.to_str().unwrap())?;
    // load returns nil + message, loadfile too, dofile raises
    let (f, err): (Option<mlua::Function>, String) = lua.load("return load(bytecode)").eval()?;
    assert!(f.is_none());
    assert!(err.contains("binary chunk"), "{err}");
    let (f, err): (Option<mlua::Function>, String) = lua.load("return loadfile(file)").eval()?;
    assert!(f.is_none());
    assert!(err.contains("binary chunk"), "{err}");
    assert!(lua.load("dofile(file)").exec().is_err());
    assert!(lua.load(&*bytecode.as_bytes()).exec().is_err());
    // text chunks and string.dump are not affected
    let n: i32 = lua.load("return load('return 1')()").eval()?;
    assert_eq!(n, 1);
    let _: mlua::LuaString = lua.load("return string.dump(function() end)").eval()?;

    // not jailed
    let n: i32 = free.load("return load(...)()").call(bytecode)?;
    assert_eq!(n, 42);
    Ok(())
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_jail_binary_chunk_async() -> Result<()> {
    // mlua caches its internal chunks as bytecode; they must still load
    let lua = jailed(JailOptions {
        deny_binary_chunk: true,
        ..Default::default()
    });
    let f = lua.create_async_function(|_, n: i32| async move { Ok(n + 1) })?;
    for i in 0..3 {
        let n: i32 = f.call_async(i).await?;
        assert_eq!(n, i + 1);
    }
    let bound = f.bind(1)?;
    let n: i32 = bound.call_async(()).await?;
    assert_eq!(n, 2);
    let n: i32 = bound.call_async(()).await?;
    assert_eq!(n, 2);
    Ok(())
}

#[test]
fn test_jail_closed_stdin() -> Result<()> {
    // io.stdin is a closed handle: reading it must be a Lua error, not a crash
    let lua = jailed(JailOptions {
        deny_open_stdin: true,
        ..Default::default()
    });
    assert!(lua.load("io.read()").exec().is_err());
    assert!(lua.load("io.stdin:read()").exec().is_err());
    assert!(lua.load("for _ in io.lines() do end").exec().is_err());
    let s: String = lua.load("return tostring(io.stdin)").eval()?;
    assert_eq!(s, "file (closed)");
    Ok(())
}

/// `io.open(path, mode)` passes the jail (and fopen)
fn can_open_mode(lua: &Lua, path: &std::path::Path, mode: &str) -> Result<bool> {
    lua.load("local ok, f = pcall(io.open, ...) if ok and f then f:close() end return ok and f ~= nil")
        .call((path.to_str().unwrap(), mode))
}

#[test]
fn test_jail_open_mode() -> Result<()> {
    let dir = temp_dir("mode");
    std::fs::write(dir.join("r.txt"), "r").unwrap();
    std::fs::write(dir.join("w.log"), "w").unwrap();
    let lua = jailed(JailOptions {
        io_root: Some(dir.clone()),
        deny_tmp: true,
        read_extension_allowlist: Some(vec!["txt".into()]),
        write_extension_allowlist: Some(vec!["log".into()]),
        ..Default::default()
    });
    assert!(can_open_mode(&lua, &dir.join("r.txt"), "r")?);
    assert!(can_open_mode(&lua, &dir.join("r.txt"), "rb")?);
    assert!(can_open_mode(&lua, &dir.join("w.log"), "w")?);
    assert!(can_open_mode(&lua, &dir.join("w.log"), "a")?);
    // '+' reads and writes, so both lists must allow it
    for mode in ["r+", "r+b", "w+", "a+", "a+b"] {
        assert!(!can_open_mode(&lua, &dir.join("r.txt"), mode)?, "{mode}");
        assert!(!can_open_mode(&lua, &dir.join("w.log"), mode)?, "{mode}");
    }
    assert_eq!(std::fs::read_to_string(dir.join("r.txt")).unwrap(), "r");
    Ok(())
}

#[test]
fn test_jail_rename_extension() -> Result<()> {
    let dir = temp_dir("rename");
    std::fs::write(dir.join("a.txt"), "a").unwrap();
    std::fs::write(dir.join("b.dat"), "b").unwrap();
    let lua = jailed(JailOptions {
        io_root: Some(dir.clone()),
        deny_tmp: true,
        write_extension_allowlist: Some(vec!["txt".into()]),
        ..Default::default()
    });
    let rename = |from: &str, to: &str| -> Result<bool> {
        lua.load("return os.rename(...) ~= nil")
            .call((dir.join(from).to_str().unwrap(), dir.join(to).to_str().unwrap()))
    };
    assert!(!rename("a.txt", "a.lua")?);
    assert!(!rename("b.dat", "b.txt")?);
    assert!(rename("a.txt", "c.txt")?);
    assert!(dir.join("c.txt").exists() && dir.join("b.dat").exists());

    // directories are not checked
    std::fs::create_dir(dir.join("d")).unwrap();
    std::fs::write(dir.join("f"), "f").unwrap();
    assert!(rename("d", ".d2")?);
    assert!(rename(".d2", "d.lua")?);
    // a file without an extension is
    assert!(!rename("f", "f2")?);
    assert!(dir.join("d.lua").is_dir() && dir.join("f").exists());
    Ok(())
}

#[test]
fn test_jail_long_extension() -> Result<()> {
    // an extension longer than the buffer must not be compared truncated
    let ext = "a".repeat(255);
    let lua = jailed(JailOptions {
        write_extension_allowlist: Some(vec![ext.clone()]),
        ..Default::default()
    });
    let passes = |name: String| -> Result<bool> {
        lua.load("return (pcall(io.open, ..., 'w'))").call(name)
    };
    // the jail passes it, then fopen fails (too long for a file name)
    assert!(passes(format!("x.{ext}"))?);
    assert!(!passes(format!("x.{ext}aaa"))?);
    Ok(())
}

#[cfg(windows)]
#[test]
fn test_jail_ansi_path() -> Result<()> {
    // in CP932, 0x95 0x5C is one character: fopen sees `a?b\..\..` (two levels up
    // from root), while a UTF-8 view sees `a?\b\..\..` (stays in root)
    let root = temp_dir("ansi").join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.parent().unwrap().join("secret.txt"), "s").unwrap();
    let lua = jailed(JailOptions {
        io_root: Some(root.clone()),
        deny_tmp: true,
        ..Default::default()
    });
    let mut path = root.to_str().unwrap().as_bytes().to_vec();
    path.extend_from_slice(b"\\a\x95\\b\\..\\..\\secret.txt");
    let opened: bool = lua.load("return io.open(...) ~= nil").call(lua.create_string(&path)?)?;
    assert!(!opened);
    Ok(())
}

#[test]
fn test_jail_link() -> Result<()> {
    let base = temp_dir("link");
    let root = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), "s").unwrap();
    std::fs::write(root.join("ok.txt"), "o").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    #[cfg(windows)]
    {
        // a junction does not need the privilege for symbolic links
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("link"))
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
    let lua = jailed(JailOptions {
        io_root: Some(root.clone()),
        deny_tmp: true,
        ..Default::default()
    });
    assert!(can_open(&lua, &root.join("ok.txt"))?);
    assert!(can_open_mode(&lua, &root.join("new.txt"), "w")?);
    assert!(!can_open(&lua, &root.join("link").join("secret.txt"))?);
    assert!(!can_open_mode(&lua, &root.join("link").join("new.txt"), "w")?);
    assert!(!outside.join("new.txt").exists());
    #[cfg(unix)]
    {
        // a dangling link would be followed by fopen "w"
        std::os::unix::fs::symlink(outside.join("dangling.txt"), root.join("dangling.txt")).unwrap();
        assert!(!can_open_mode(&lua, &root.join("dangling.txt"), "w")?);
        assert!(!outside.join("dangling.txt").exists());
    }
    Ok(())
}

#[test]
fn test_jail_tmp_dir() -> Result<()> {
    let root = temp_dir("tmp");
    let open_tmpname = "local name = os.tmpname() local f = io.open(name, 'w') if f then f:close() os.remove(name) end return f ~= nil";
    let lua = jailed(JailOptions {
        io_root: Some(root.clone()),
        ..Default::default()
    });
    assert!(lua.load(open_tmpname).eval::<bool>()?);
    let lua = jailed(JailOptions {
        io_root: Some(root),
        deny_tmp: true,
        ..Default::default()
    });
    assert!(!lua.load(open_tmpname).eval::<bool>()?);
    Ok(())
}

/// Sets a variable where Lua's `os.getenv` sees it. On Windows the CRT keeps its own copy of the
/// environment, which `std::env::set_var` (SetEnvironmentVariableW) does not update
fn set_env(name: &str, value: &str) {
    #[cfg(windows)]
    {
        unsafe extern "C" {
            fn _putenv_s(name: *const std::ffi::c_char, value: *const std::ffi::c_char) -> i32;
        }
        let name = std::ffi::CString::new(name).unwrap();
        let value = std::ffi::CString::new(value).unwrap();
        assert_eq!(unsafe { _putenv_s(name.as_ptr(), value.as_ptr()) }, 0);
    }
    #[cfg(not(windows))]
    // SAFETY: no other test reads or writes these variables
    unsafe {
        std::env::set_var(name, value)
    };
}

#[test]
fn test_jail_getenv_prefix() -> Result<()> {
    set_env("MLUA_JAIL_TEST_ALLOWED", "yes");
    set_env("MLUA_JAIL_OTHER", "no");
    let lua = jailed(JailOptions {
        getenv: GetEnvOption::Prefix("MLUA_JAIL_TEST_".to_string()),
        ..Default::default()
    });
    let getenv = |name: &str| -> Result<Option<String>> {
        lua.load("return os.getenv(...)").call(name)
    };
    assert_eq!(getenv("MLUA_JAIL_TEST_ALLOWED")?.as_deref(), Some("yes"));
    assert_eq!(getenv("MLUA_JAIL_OTHER")?, None);
    assert_eq!(getenv("MLUA_JAIL_TEST")?, None);
    assert_eq!(getenv("PATH")?, None);
    // Windows does not distinguish the case of variable names
    let lower = getenv("mlua_jail_test_allowed")?;
    if cfg!(windows) {
        assert_eq!(lower.as_deref(), Some("yes"));
    } else {
        assert_eq!(lower, None);
    }
    Ok(())
}
