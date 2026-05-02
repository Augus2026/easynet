use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["proto/message.proto"], &["proto/"])?;
    copy_wintun_dll()?;
    Ok(())
}

fn copy_wintun_dll() -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET")?;
    let Some(arch) = wintun_arch(&target) else {
        return Ok(());
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let version = locked_wintun_bindings_version(&manifest_dir.join("Cargo.lock"))?;
    let wintun_dll = find_wintun_dll(&version, arch)?;
    let output_dir = build_output_dir()?;

    fs::copy(&wintun_dll, output_dir.join("wintun.dll"))?;
    println!("cargo:rerun-if-changed=Cargo.lock");
    Ok(())
}

fn wintun_arch(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-pc-windows-msvc" | "x86_64-pc-windows-gnu" => Some("amd64"),
        "i686-pc-windows-msvc" | "i686-pc-windows-gnu" => Some("x86"),
        "aarch64-pc-windows-msvc" | "aarch64-pc-windows-gnullvm" => Some("arm64"),
        "armv7-pc-windows-msvc" => Some("arm"),
        _ => None,
    }
}

fn locked_wintun_bindings_version(lockfile: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let lockfile = fs::read_to_string(lockfile)?;
    let mut in_package = false;

    for line in lockfile.lines() {
        if line == "[[package]]" {
            in_package = false;
            continue;
        }

        if line == "name = \"wintun-bindings\"" {
            in_package = true;
            continue;
        }

        if in_package {
            if let Some(version) = line.strip_prefix("version = \"") {
                return Ok(version.trim_end_matches('"').to_string());
            }
        }
    }

    Err("wintun-bindings is missing from Cargo.lock".into())
}

fn find_wintun_dll(version: &str, arch: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("CARGO_HOME, USERPROFILE, and HOME are unavailable")?;

    let registry_src = cargo_home.join("registry").join("src");
    let crate_dir_name = format!("wintun-bindings-{version}");

    for registry in fs::read_dir(&registry_src)? {
        let crate_dir = registry?.path().join(&crate_dir_name);
        let dll = crate_dir.join("wintun").join("bin").join(arch).join("wintun.dll");
        if dll.exists() {
            return Ok(dll);
        }
    }

    Err(format!(
        "wintun.dll not found for wintun-bindings {version} and arch {arch}"
    )
    .into())
}

fn build_output_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .ok_or("Unable to determine Cargo profile output directory")?;
    Ok(profile_dir.to_path_buf())
}
