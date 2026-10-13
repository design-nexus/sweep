use crate::nmap::xml::ScanDocument;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub started: DateTime<Utc>,
    pub finished: Option<DateTime<Utc>>,
    pub argv: Vec<String>,
    pub targets: String,
    pub profile: Option<String>,
    pub dir: PathBuf,
    pub status: String,
    pub hosts_up: u32,
    pub hosts_total: u32,
    pub command: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HistoryFile {
    pub entries: Vec<HistoryEntry>,
}

pub struct Paths {
    #[allow(dead_code)]
    pub data: PathBuf,
    pub scans: PathBuf,
    pub history: PathBuf,
    #[allow(dead_code)]
    pub config: PathBuf,
}

impl Paths {
    pub fn resolve() -> anyhow::Result<Self> {
        let data = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nexus-map");
        let config = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nexus-map");
        std::fs::create_dir_all(data.join("scans"))?;
        std::fs::create_dir_all(&config)?;
        Ok(Self {
            scans: data.join("scans"),
            history: data.join("history.toml"),
            data,
            config,
        })
    }
}

pub fn load_history(path: &Path) -> HistoryFile {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_history(path: &Path, hist: &HistoryFile) -> anyhow::Result<()> {
    let s = toml::to_string_pretty(hist)?;
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))
}

pub fn upsert(hist: &mut HistoryFile, entry: HistoryEntry) {
    if let Some(e) = hist.entries.iter_mut().find(|e| e.id == entry.id) {
        *e = entry;
    } else {
        hist.entries.insert(0, entry);
    }
}

pub fn load_scan_xml(dir: &Path) -> anyhow::Result<ScanDocument> {
    let xml = std::fs::read_to_string(dir.join("scan.xml"))
        .with_context(|| format!("read {}/scan.xml", dir.display()))?;
    crate::nmap::xml::parse_document(&xml)
}

pub fn write_meta(dir: &Path, entry: &HistoryEntry) -> anyhow::Result<()> {
    let s = toml::to_string_pretty(entry)?;
    std::fs::write(dir.join("meta.toml"), s)?;
    Ok(())
}

/// Delete only a direct scan directory owned by this application's scan root.
pub fn delete_scan(scans: &Path, dir: &Path) -> anyhow::Result<()> {
    let root = scans.canonicalize().context("resolve scan root")?;
    let parent = dir
        .parent()
        .context("scan directory has no parent")?
        .canonicalize()
        .context("resolve scan parent")?;
    anyhow::ensure!(
        parent == root,
        "refusing to delete a directory outside the scan root"
    );
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            anyhow::ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "scan path is not an owned directory"
            );
            let resolved = dir.canonicalize()?;
            anyhow::ensure!(
                resolved.parent() == Some(root.as_path()),
                "scan path escapes the scan root"
            );
            std::fs::remove_dir_all(dir).context("delete scan directory")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod deletion_tests {
    #[test]
    fn deletion_rejects_external_paths_and_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("scans");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        assert!(super::delete_scan(&root, &outside).is_err());
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(super::delete_scan(&root, &link).is_err());
        assert!(super::delete_scan(&root, &root).is_err());
        let owned = root.join("owned");
        std::fs::create_dir(&owned).unwrap();
        super::delete_scan(&root, &owned).unwrap();
        assert!(!owned.exists());
        assert!(outside.exists());
        super::delete_scan(&root, &owned).unwrap();
    }
}
