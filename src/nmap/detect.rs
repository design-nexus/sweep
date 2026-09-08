use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Default)]
pub struct NmapInfo {
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub euid_root: bool,
}

impl NmapInfo {
    pub fn present(&self) -> bool {
        self.path.is_some()
    }

    pub fn version_short(&self) -> &str {
        self.version.as_deref().unwrap_or("not installed")
    }

    pub fn binary(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

pub fn detect() -> NmapInfo {
    let path = which("nmap");
    let version = path.as_ref().and_then(|p| {
        Command::new(p)
            .arg("-V")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.to_ascii_lowercase().contains("nmap version"))
                    .map(|l| l.trim().to_string())
            })
    });
    NmapInfo {
        path,
        version,
        euid_root: euid() == 0,
    }
}

pub fn which(bin: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("NMAP") {
        let p = PathBuf::from(&explicit);
        if p.exists() {
            return Some(p);
        }
    }
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let p = Path::new(dir).join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}
