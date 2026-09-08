use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct NseScript {
    pub name: String,
    pub categories: Vec<String>,
}

pub const CATEGORIES: &[&str] = &[
    "auth",
    "broadcast",
    "brute",
    "default",
    "discovery",
    "dos",
    "exploit",
    "external",
    "fuzzer",
    "intrusive",
    "malware",
    "safe",
    "version",
    "vuln",
];

pub fn load_catalog() -> Vec<NseScript> {
    for dir in [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/opt/nmap/scripts",
    ] {
        let p = Path::new(dir);
        if p.is_dir() {
            let mut v = read_dir(p);
            if !v.is_empty() {
                v.sort_by(|a, b| a.name.cmp(&b.name));
                return v;
            }
        }
    }
    builtin()
}

fn read_dir(dir: &Path) -> Vec<NseScript> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "nse"))
        .map(|e| {
            let name = e
                .path()
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let cats = fs::read_to_string(e.path())
                .ok()
                .and_then(|s| parse_categories(&s))
                .unwrap_or_default();
            NseScript {
                name,
                categories: cats,
            }
        })
        .collect()
}

fn parse_categories(src: &str) -> Option<Vec<String>> {
    let idx = src.find("categories")?;
    let rest = &src[idx..];
    let start = rest.find('{')?;
    let end = rest[start..].find('}')?;
    let body = &rest[start + 1..start + end];
    let cats = body
        .split(',')
        .filter_map(|p| {
            let t = p.trim().trim_matches('"').trim_matches('\'').trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
        .collect::<Vec<_>>();
    Some(cats)
}

fn builtin() -> Vec<NseScript> {
    const PAIRS: &[(&str, &str)] = &[
        ("http-title", "default,discovery,safe"),
        ("http-headers", "discovery,safe"),
        ("http-methods", "discovery"),
        ("ssl-cert", "default,discovery,safe"),
        ("ssl-enum-ciphers", "discovery,intrusive"),
        ("ssh-hostkey", "default,discovery,safe"),
        ("ssh-auth-methods", "default,safe"),
        ("smb-os-discovery", "default,discovery,safe"),
        ("smb-enum-shares", "discovery"),
        ("smb-vuln-ms17-010", "intrusive,vuln"),
        ("ftp-anon", "auth,default,discovery,safe"),
        ("dns-recursion", "discovery"),
        ("snmp-info", "default,discovery,safe"),
        ("mysql-info", "default,discovery,safe"),
        ("rdp-enum-encryption", "discovery,safe"),
        ("banner", "discovery"),
        ("vulners", "vuln,safe,external"),
        ("http-vuln-cve2017-5638", "vuln"),
        ("ssl-heartbleed", "vuln,safe"),
        ("ssl-poodle", "vuln,safe"),
        ("smb-security-mode", "discovery,safe"),
        ("broadcast-dhcp-discover", "broadcast,discovery"),
        ("nbstat", "default,discovery,safe"),
        ("rpcinfo", "discovery,safe"),
        ("nfs-showmount", "discovery,safe"),
        ("http-enum", "discovery,intrusive"),
        ("http-wordpress-enum", "discovery,intrusive"),
        ("smtp-commands", "default,discovery,safe"),
        ("imap-capabilities", "default,discovery,safe"),
        ("pop3-capabilities", "default,discovery,safe"),
        ("telnet-encryption", "discovery,safe"),
        ("ajp-headers", "discovery,safe"),
        ("mongodb-info", "discovery,safe"),
        ("redis-info", "discovery,safe"),
        ("docker-version", "discovery,safe"),
        ("kubernetes-version", "discovery"),
    ];
    PAIRS
        .iter()
        .map(|(n, c)| NseScript {
            name: (*n).into(),
            categories: c.split(',').map(|s| s.to_string()).collect(),
        })
        .collect()
}
