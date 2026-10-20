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
