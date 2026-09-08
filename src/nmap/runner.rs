use super::args::ScanSpec;
use super::detect::NmapInfo;
use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum ScanEvent {
    Stdout(String),
    Stderr(String),
    #[allow(dead_code)]
    Exited {
        code: Option<i32>,
    },
}

pub struct LiveScan {
    pub id: String,
    pub dir: PathBuf,
    pub xml_path: PathBuf,
    pub pid: u32,
    pub child: Option<Child>,
    pub argv: Vec<String>,
    pub display_cmd: String,
    pub started: DateTime<Utc>,
    pub log: Vec<String>,
    pub stats_line: String,
    pub cancel_requested: bool,
    pub cancel_at: Option<Instant>,
    pub used_sudo: bool,
}

impl LiveScan {
    pub fn running(&self) -> bool {
        self.child.is_some()
    }

    pub fn request_cancel(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGINT);
                }
            }
            self.cancel_requested = true;
            self.cancel_at = Some(Instant::now());
        }
    }

    pub fn force_kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

pub async fn start(
    spec: &ScanSpec,
    info: &NmapInfo,
    scans_root: &Path,
    escalate: bool,
) -> anyhow::Result<(LiveScan, mpsc::Receiver<ScanEvent>)> {
    let bin = info
        .binary()
        .ok_or_else(|| anyhow::anyhow!("nmap is not installed or not on PATH"))?;

    let id = Uuid::new_v4().to_string()[..8].to_string();
    let stamp = Utc::now().format("%Y%m%dT%H%M%S");
    let dir = scans_root.join(format!("{stamp}-{id}"));
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let base = dir.join("scan");
    let xml_path = dir.join("scan.xml");

    let mut nmap_args = spec.to_argv();
    // Runner-owned output. Insert before targets so nmap still sees flags first.
    let targets = spec.target_list();
    if !targets.is_empty() {
        nmap_args.truncate(nmap_args.len() - targets.len());
    }
    nmap_args.push("--stats-every".into());
    nmap_args.push("1s".into());
    nmap_args.push("-oA".into());
    nmap_args.push(base.to_string_lossy().into_owned());
    nmap_args.extend(targets);

    let used_sudo = escalate && spec.needs_root() && !info.euid_root;
    let mut cmd = if used_sudo {
        let mut c = Command::new("sudo");
        c.arg("-n");
        c.arg(bin);
        c
    } else {
        Command::new(bin)
    };
    cmd.args(&nmap_args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    cmd.kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    let pid = child.id().unwrap_or(0);
    let stdout = child.stdout.take().context("stdout")?;
    let stderr = child.stderr.take().context("stderr")?;

    let (tx, rx) = mpsc::channel::<ScanEvent>(256);
    let tx_out = tx.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx_out.send(ScanEvent::Stdout(line)).await.is_err() {
                break;
            }
        }
    });
    let tx_err = tx.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx_err.send(ScanEvent::Stderr(line)).await.is_err() {
                break;
            }
        }
    });

    let display_cmd = {
        let mut p = Vec::new();
        if used_sudo {
            p.push("sudo".into());
            p.push("-n".into());
        }
        p.push("nmap".into());
        p.extend(nmap_args.iter().cloned());
        p.join(" ")
    };

    let scan = LiveScan {
        id,
        dir,
        xml_path,
        pid,
        child: Some(child),
        argv: nmap_args,
        display_cmd,
        started: Utc::now(),
        log: Vec::new(),
        stats_line: String::new(),
        cancel_requested: false,
        cancel_at: None,
        used_sudo,
    };

    // Waiter is polled from App via try_wait; also keep child in scan.
    let _ = tx; // clone already spawned
    if scan.pid == 0 {
        bail!("failed to read child pid");
    }
    Ok((scan, rx))
}

pub fn looks_like_stats(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("stats:") || l.contains("timing:") || l.contains("about ") && l.contains("% done")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::args::ScanSpec;
    use crate::nmap::detect::NmapInfo;
    use crate::nmap::xml::parse_partial;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn mock_binary_produces_host() {
        let tmp = std::env::temp_dir().join(format!("nexus-map-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let fake = tmp.join("nmap");
        std::fs::write(
            &fake,
            r#"#!/bin/sh
base=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-oA" ]; then
    base="$2"
    shift
  fi
  shift
done
echo "Starting Nmap 7.95 ( https://nmap.org )"
echo "Nmap scan report for 10.0.0.1"
printf '%s\n' '<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1" startstr="now" version="7.95" xmloutputversion="1.04">
<host><status state="up" reason="syn-ack"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port></ports>
</host>
<runstats><finished time="1" timestr="now" elapsed="0.1" summary="done" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>' > "${base}.xml"
echo "Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let info = NmapInfo {
            path: Some(fake),
            version: Some("Nmap version 7.95".into()),
            euid_root: true,
        };
        let mut spec = ScanSpec::default();
        spec.targets = "10.0.0.1".into();
        spec.tcp_scan = crate::nmap::args::TcpScan::Connect;
        let scans = tmp.join("scans");
        let (mut live, mut rx) = start(&spec, &info, &scans, false).await.unwrap();
        let mut lines = Vec::new();
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    if let Some(ScanEvent::Stdout(l) | ScanEvent::Stderr(l)) = ev {
                        lines.push(l);
                    }
                }
                status = live.child.as_mut().unwrap().wait() => {
                    assert!(status.unwrap().success());
                    break;
                }
            }
        }
        let xml = std::fs::read_to_string(&live.xml_path).unwrap();
        let doc = parse_partial(&xml);
        assert_eq!(doc.hosts.len(), 1);
        assert_eq!(doc.hosts[0].primary_ip(), "10.0.0.1");
        assert!(lines.iter().any(|l| l.contains("Nmap done")));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
