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

    let previous = if let Some(path) = &spec.resume {
        let path = Path::new(path);
        if !path.is_file() {
            bail!("resume output does not exist: {}", path.display());
        }
        let parent = path.parent().context("resume output directory")?;
        std::fs::read_to_string(parent.join("meta.toml"))
            .ok()
            .and_then(|s| toml::from_str::<crate::persist::HistoryEntry>(&s).ok())
    } else {
        None
    };
    let id = previous
        .as_ref()
        .map(|e| e.id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string()[..8].to_string());
    let stamp = Utc::now().format("%Y%m%dT%H%M%S");
    let dir = if let Some(path) = &spec.resume {
        Path::new(path)
            .parent()
            .context("resume directory")?
            .to_path_buf()
    } else {
        scans_root.join(format!("{stamp}-{id}"))
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let base = dir.join("scan");
    let xml_path = if let Some(path) = &spec.resume {
        Path::new(path).with_extension("xml")
    } else {
        dir.join("scan.xml")
    };
    let mut nmap_args = spec.to_argv();
    if spec.resume.is_none() {
        let targets = spec.target_list();
        if !targets.is_empty() {
            nmap_args.truncate(nmap_args.len() - targets.len());
        }
        nmap_args.extend([
            "--stats-every".into(),
            "1s".into(),
            "-oA".into(),
            base.to_string_lossy().into_owned(),
        ]);
        nmap_args.extend(targets);
    }

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
        argv: previous
            .as_ref()
            .map(|e| e.argv.clone())
            .unwrap_or(nmap_args),
        display_cmd,
        started: previous
            .as_ref()
            .map(|e| e.started)
            .unwrap_or_else(Utc::now),
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
    async fn resume_reuses_output_and_passes_only_resume_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let scans = dir.path().join("a scan");
        std::fs::create_dir(&scans).unwrap();
        let output = scans.join("scan.nmap");
        std::fs::write(&output, "interrupted").unwrap();
        let args = dir.path().join("args");
        let fake = dir.path().join("fake-nmap");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", args.display()),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let original = crate::persist::HistoryEntry {
            id: "old-scan".into(),
            started: Utc::now(),
            finished: None,
            argv: vec!["-sT".into(), "192.0.2.1".into()],
            targets: "192.0.2.1".into(),
            profile: None,
            dir: scans.clone(),
            status: "interrupted".into(),
            hosts_up: 0,
            hosts_total: 0,
            command: "nmap -sT 192.0.2.1".into(),
        };
        crate::persist::write_meta(&scans, &original).unwrap();
        let info = NmapInfo {
            path: Some(fake),
            version: None,
            euid_root: true,
        };
        let spec = ScanSpec {
            resume: Some(output.to_string_lossy().into()),
            targets: original.targets.clone(),
            ..Default::default()
        };
        let (mut live, _) = start(&spec, &info, &dir.path().join("unused"), false)
            .await
            .unwrap();
        assert!(live.child.as_mut().unwrap().wait().await.unwrap().success());
        assert_eq!(
            std::fs::read_to_string(args).unwrap(),
            format!("--resume\n{}\n", output.display())
        );
        assert_eq!(live.dir, scans);
        assert_eq!(live.xml_path, scans.join("scan.xml"));
        assert_eq!(live.id, "old-scan");
        assert_eq!(live.argv, original.argv);
    }
    #[tokio::test]
    async fn mock_binary_produces_host() {
        let tmp = std::env::temp_dir().join(format!("sweep-test-{}", Uuid::new_v4()));
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
        // Child exit can arrive before the pipe-reader tasks deliver their final lines.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(event) = rx.recv().await {
                if let ScanEvent::Stdout(line) | ScanEvent::Stderr(line) = event {
                    lines.push(line);
                }
            }
        })
        .await
        .expect("reader tasks close after the mock child exits");
        let xml = std::fs::read_to_string(&live.xml_path).unwrap();
        let doc = parse_partial(&xml);
        assert_eq!(doc.hosts.len(), 1);
        assert_eq!(doc.hosts[0].primary_ip(), "10.0.0.1");
        assert!(lines.iter().any(|l| l.contains("Nmap done")));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
