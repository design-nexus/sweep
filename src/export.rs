use crate::nmap::xml::ScanDocument;
use anyhow::Context;
use std::path::Path;

pub fn to_json(doc: &ScanDocument) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(doc)?)
}

pub fn to_markdown(doc: &ScanDocument) -> String {
    let mut s = String::new();
    s.push_str("# Nmap scan\n\n");
    if !doc.args.is_empty() {
        s.push_str(&format!("`{}`\n\n", doc.args));
    }
    if let Some(f) = &doc.finished {
        s.push_str(&format!("{}\n\n", f.summary));
    }
    for host in &doc.hosts {
        s.push_str(&format!("## {} {}\n\n", host.primary_ip(), host.hostname()));
        s.push_str(&format!(
            "- status: **{}** ({})\n",
            host.status, host.reason
        ));
        if !host.os_guess().is_empty() {
            s.push_str(&format!("- os: {}\n", host.os_guess()));
        }
        s.push_str("\n| Port | Proto | State | Service | Version |\n|---|---|---|---|---|\n");
        for p in &host.ports {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} {} |\n",
                p.portid, p.protocol, p.state, p.service, p.product, p.version
            ));
        }
        s.push('\n');
        for sc in host
            .ports
            .iter()
            .flat_map(|p| p.scripts.iter())
            .chain(host.host_scripts.iter())
        {
            s.push_str(&format!("### {}\n\n```\n{}\n```\n\n", sc.id, sc.output));
        }
    }
    s
}

pub fn to_csv(doc: &ScanDocument) -> String {
    let mut s = String::from("ip,hostname,port,proto,state,service,product,version\n");
    for host in &doc.hosts {
        for p in &host.ports {
            s.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                host.primary_ip(),
                escape_csv(host.hostname()),
                p.portid,
                p.protocol,
                p.state,
                escape_csv(&p.service),
                escape_csv(&p.product),
                escape_csv(&p.version)
            ));
        }
        if host.ports.is_empty() {
            s.push_str(&format!(
                "{},{},,,,,,\n",
                host.primary_ip(),
                escape_csv(host.hostname())
            ));
        }
    }
    s
}

fn escape_csv(v: &str) -> String {
    if v.contains([',', '"', '\n']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

pub fn write(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

#[derive(Clone, Copy)]
pub enum Format {
    Json,
    Markdown,
    Csv,
}

impl Format {
    pub fn render(self, doc: &ScanDocument) -> anyhow::Result<String> {
        match self {
            Format::Json => to_json(doc),
            Format::Markdown => Ok(to_markdown(doc)),
            Format::Csv => Ok(to_csv(doc)),
        }
    }
}

pub fn compare(a: &ScanDocument, b: &ScanDocument) -> Vec<DiffLine> {
    let mut lines = Vec::new();
    let ips = |d: &ScanDocument| {
        d.hosts
            .iter()
            .map(|h| h.primary_ip().to_string())
            .collect::<Vec<_>>()
    };
    let a_ips = ips(a);
    let b_ips = ips(b);
    for ip in &b_ips {
        if !a_ips.iter().any(|x| x == ip) {
            lines.push(DiffLine {
                kind: DiffKind::Added,
                text: format!("host {ip} added"),
            });
        }
    }
    for ip in &a_ips {
        if !b_ips.iter().any(|x| x == ip) {
            lines.push(DiffLine {
                kind: DiffKind::Removed,
                text: format!("host {ip} removed"),
            });
        }
    }
    for hb in &b.hosts {
        if let Some(ha) = a.hosts.iter().find(|h| h.primary_ip() == hb.primary_ip()) {
            for pb in &hb.ports {
                let pa = ha
                    .ports
                    .iter()
                    .find(|p| p.protocol == pb.protocol && p.portid == pb.portid);
                match pa {
                    None => lines.push(DiffLine {
                        kind: DiffKind::Added,
                        text: format!(
                            "{} {}/{} {} {}",
                            hb.primary_ip(),
                            pb.portid,
                            pb.protocol,
                            pb.state,
                            pb.service
                        ),
                    }),
                    Some(pa) if pa.state != pb.state => lines.push(DiffLine {
                        kind: DiffKind::Changed,
                        text: format!(
                            "{} {}/{} {} → {}",
                            hb.primary_ip(),
                            pb.portid,
                            pb.protocol,
                            pa.state,
                            pb.state
                        ),
                    }),
                    _ => {}
                }
            }
            for pa in &ha.ports {
                if !hb
                    .ports
                    .iter()
                    .any(|p| p.protocol == pa.protocol && p.portid == pa.portid)
                {
                    lines.push(DiffLine {
                        kind: DiffKind::Removed,
                        text: format!(
                            "{} {}/{} {} {}",
                            ha.primary_ip(),
                            pa.portid,
                            pa.protocol,
                            pa.state,
                            pa.service
                        ),
                    });
                }
            }
        }
    }
    if lines.is_empty() {
        lines.push(DiffLine {
            kind: DiffKind::Same,
            text: "no differences".into(),
        });
    }
    lines
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    Added,
    Removed,
    Changed,
    Same,
}

#[derive(Clone, Debug)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}
