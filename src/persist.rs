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
