use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanDocument {
    pub scanner: String,
    pub args: String,
    pub startstr: String,
    pub version: String,
    pub xmloutputversion: String,
    pub scaninfo: Vec<ScanInfo>,
    pub hosts: Vec<Host>,
    pub finished: Option<Finished>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanInfo {
    pub scan_type: String,
    pub protocol: String,
    pub numservices: String,
    pub services: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Finished {
    pub time: String,
    pub elapsed: String,
    pub summary: String,
    pub exit: String,
    pub hosts_up: String,
    pub hosts_down: String,
    pub hosts_total: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub status: String,
    pub reason: String,
    pub addresses: Vec<Address>,
    pub hostnames: Vec<String>,
    pub ports: Vec<Port>,
    pub extraports: Vec<ExtraPorts>,
    pub os_matches: Vec<OsMatch>,
    pub hops: Vec<Hop>,
    pub host_scripts: Vec<Script>,
    pub distance: Option<String>,
    pub raw: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Address {
    pub addr: String,
    pub addrtype: String,
    pub vendor: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub protocol: String,
    pub portid: String,
    pub state: String,
    pub reason: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub extrainfo: String,
    pub scripts: Vec<Script>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ExtraPorts {
    pub state: String,
    pub count: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: String,
    pub osfamily: String,
    pub vendor: String,
    pub osgen: String,
    pub cpe: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: String,
    pub ipaddr: String,
    pub rtt: String,
    pub host: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Script {
    pub id: String,
    pub output: String,
}

impl Host {
    pub fn primary_ip(&self) -> &str {
        self.addresses
            .iter()
            .find(|a| a.addrtype == "ipv4")
            .or_else(|| self.addresses.iter().find(|a| a.addrtype == "ipv6"))
            .map(|a| a.addr.as_str())
            .unwrap_or("-")
    }

    pub fn hostname(&self) -> &str {
        self.hostnames.first().map(|s| s.as_str()).unwrap_or("")
    }

    pub fn open_ports(&self) -> impl Iterator<Item = &Port> {
        self.ports.iter().filter(|p| p.state == "open")
    }

    pub fn os_guess(&self) -> &str {
        self.os_matches
            .first()
            .map(|o| o.name.as_str())
            .unwrap_or("")
    }
}

impl ScanDocument {
    pub fn merge_partial(&mut self, other: ScanDocument) {
        if !other.args.is_empty() {
            self.args = other.args;
        }
        if !other.startstr.is_empty() {
            self.startstr = other.startstr;
        }
        if !other.version.is_empty() {
            self.version = other.version;
        }
        if !other.scaninfo.is_empty() {
            self.scaninfo = other.scaninfo;
        }
        for host in other.hosts {
            let ip = host.primary_ip().to_string();
            if let Some(existing) = self.hosts.iter_mut().find(|h| h.primary_ip() == ip) {
                *existing = host;
            } else {
                self.hosts.push(host);
            }
        }
        if other.finished.is_some() {
            self.finished = other.finished;
        }
        self.truncated = other.truncated;
    }

    pub fn hosts_up(&self) -> usize {
        self.hosts.iter().filter(|h| h.status == "up").count()
    }
}

pub fn parse_document(xml: &str) -> anyhow::Result<ScanDocument> {
    let doc = parse_partial(xml);
    if doc.hosts.is_empty() && !xml.contains("<host") && xml.trim().is_empty() {
        anyhow::bail!("empty nmap xml");
    }
    Ok(doc)
}

/// Parse whatever complete `<host>` elements exist. Incomplete trailing host is skipped.
pub fn parse_partial(xml: &str) -> ScanDocument {
    let mut doc = ScanDocument {
        truncated: !xml.contains("</nmaprun>"),
        ..Default::default()
    };
    if let Some(head) = xml.split("<host").next() {
        parse_header(head, &mut doc);
    }
    parse_runstats(xml, &mut doc);
    for slice in complete_host_slices(xml) {
        if let Some(host) = parse_host(slice) {
            doc.hosts.push(host);
        }
    }
    doc
}

fn complete_host_slices(xml: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(rel) = xml[search..].find("<host") {
        let start = search + rel;
        if !is_host_open_tag(xml, start) {
            search = start + 5;
            continue;
        }
        if let Some(end_rel) = xml[start..].find("</host>") {
            let end = start + end_rel + "</host>".len();
            out.push(&xml[start..end]);
            search = end;
        } else {
            break;
        }
    }
    out
}

fn is_host_open_tag(xml: &str, start: usize) -> bool {
    let rest = &xml[start..];
    rest.starts_with("<host ")
        || rest.starts_with("<host>")
        || rest.starts_with("<host\n")
        || rest.starts_with("<host\r")
        || rest.starts_with("<host/")
}

fn parse_header(head: &str, doc: &mut ScanDocument) {
    if let Some(tag) = tag_attrs(head, "nmaprun") {
        doc.scanner = attr(&tag, "scanner").unwrap_or_default();
        doc.args = attr(&tag, "args").unwrap_or_default();
        doc.startstr = attr(&tag, "startstr").unwrap_or_default();
        doc.version = attr(&tag, "version").unwrap_or_default();
        doc.xmloutputversion = attr(&tag, "xmloutputversion").unwrap_or_default();
    }
    let mut search = 0;
    while let Some(rel) = head[search..].find("<scaninfo") {
        let start = search + rel;
        if let Some(tag) = tag_from(head, start) {
            doc.scaninfo.push(ScanInfo {
                scan_type: attr(&tag, "type").unwrap_or_default(),
                protocol: attr(&tag, "protocol").unwrap_or_default(),
                numservices: attr(&tag, "numservices").unwrap_or_default(),
                services: attr(&tag, "services").unwrap_or_default(),
            });
            search = start + tag.len();
        } else {
            break;
        }
    }
}

fn parse_runstats(xml: &str, doc: &mut ScanDocument) {
    let hosts_up = attr_in(xml, "hosts", "up").unwrap_or_default();
    let hosts_down = attr_in(xml, "hosts", "down").unwrap_or_default();
    let hosts_total = attr_in(xml, "hosts", "total").unwrap_or_default();
    if let Some(tag) = tag_attrs(xml, "finished") {
        doc.finished = Some(Finished {
            time: attr(&tag, "timestr").unwrap_or_default(),
            elapsed: attr(&tag, "elapsed").unwrap_or_default(),
            summary: attr(&tag, "summary").unwrap_or_default(),
            exit: attr(&tag, "exit").unwrap_or_default(),
            hosts_up,
            hosts_down,
            hosts_total,
        });
    }
}

fn parse_host(xml: &str) -> Option<Host> {
    let mut host = Host {
        raw: xml.to_string(),
        ..Default::default()
    };
    if let Some(tag) = tag_attrs(xml, "status") {
        host.status = attr(&tag, "state").unwrap_or_default();
        host.reason = attr(&tag, "reason").unwrap_or_default();
    }
    let mut search = 0;
    while let Some(rel) = xml[search..].find("<address") {
        let start = search + rel;
        if let Some(tag) = tag_from(xml, start) {
            host.addresses.push(Address {
                addr: attr(&tag, "addr").unwrap_or_default(),
                addrtype: attr(&tag, "addrtype").unwrap_or_default(),
                vendor: attr(&tag, "vendor"),
            });
            search = start + tag.len();
        } else {
            break;
        }
    }
    if let Some(block) = inner_block(xml, "hostnames") {
        let mut s = 0;
        while let Some(rel) = block[s..].find("<hostname") {
            let start = s + rel;
            if let Some(tag) = tag_from(block, start) {
                if let Some(n) = attr(&tag, "name") {
                    host.hostnames.push(n);
                }
                s = start + tag.len();
            } else {
                break;
            }
        }
    }
    if let Some(block) = inner_block(xml, "ports") {
        parse_ports(block, &mut host);
    }
    parse_os(xml, &mut host);
    if let Some(block) = inner_block(xml, "trace") {
        let mut s = 0;
        while let Some(rel) = block[s..].find("<hop") {
            let start = s + rel;
            if let Some(tag) = tag_from(block, start) {
                host.hops.push(Hop {
                    ttl: attr(&tag, "ttl").unwrap_or_default(),
                    ipaddr: attr(&tag, "ipaddr").unwrap_or_default(),
                    rtt: attr(&tag, "rtt").unwrap_or_default(),
                    host: attr(&tag, "host").unwrap_or_default(),
                });
                s = start + tag.len();
            } else {
                break;
            }
        }
    }
    if let Some(block) = inner_block(xml, "hostscript") {
        host.host_scripts = parse_scripts(block);
    }
    if let Some(tag) = tag_attrs(xml, "distance") {
        host.distance = attr(&tag, "value");
    }
    Some(host)
}

fn parse_ports(block: &str, host: &mut Host) {
    let mut s = 0;
    while let Some(rel) = block[s..].find("<extraports") {
        let start = s + rel;
        if let Some(tag) = tag_from(block, start) {
            host.extraports.push(ExtraPorts {
                state: attr(&tag, "state").unwrap_or_default(),
                count: attr(&tag, "count").unwrap_or_default(),
            });
            s = start + tag.len();
        } else {
            break;
        }
    }
    s = 0;
    while let Some(rel) = block[s..].find("<port ") {
        let start = s + rel;
        let Some(end_rel) = block[start..].find("</port>") else {
            break;
        };
        let end = start + end_rel + "</port>".len();
        let slice = &block[start..end];
        if let Some(tag) = tag_from(slice, 0) {
            let mut port = Port {
                protocol: attr(&tag, "protocol").unwrap_or_default(),
                portid: attr(&tag, "portid").unwrap_or_default(),
                ..Default::default()
            };
            if let Some(st) = tag_attrs(slice, "state") {
                port.state = attr(&st, "state").unwrap_or_default();
                port.reason = attr(&st, "reason").unwrap_or_default();
            }
            if let Some(sv) = tag_attrs(slice, "service") {
                port.service = attr(&sv, "name").unwrap_or_default();
                port.product = attr(&sv, "product").unwrap_or_default();
                port.version = attr(&sv, "version").unwrap_or_default();
                port.extrainfo = attr(&sv, "extrainfo").unwrap_or_default();
            }
            port.scripts = parse_scripts(slice);
            host.ports.push(port);
        }
        s = end;
    }
}

fn parse_os(xml: &str, host: &mut Host) {
    let Some(block) = inner_block(xml, "os") else {
        return;
    };
    let mut s = 0;
    while let Some(rel) = block[s..].find("<osmatch") {
        let start = s + rel;
        let end = block[start..]
            .find("</osmatch>")
            .map(|e| start + e + "</osmatch>".len())
            .or_else(|| tag_from(block, start).map(|t| start + t.len()))
            .unwrap_or(block.len());
        let slice = &block[start..end];
        if let Some(tag) = tag_from(slice, 0) {
            let mut m = OsMatch {
                name: attr(&tag, "name").unwrap_or_default(),
                accuracy: attr(&tag, "accuracy").unwrap_or_default(),
                ..Default::default()
            };
            if let Some(cls) = tag_attrs(slice, "osclass") {
                m.osfamily = attr(&cls, "osfamily").unwrap_or_default();
                m.vendor = attr(&cls, "vendor").unwrap_or_default();
                m.osgen = attr(&cls, "osgen").unwrap_or_default();
            }
            let mut cs = 0;
            while let Some(rel) = slice[cs..].find("<cpe>") {
                let a = cs + rel + 5;
                if let Some(b) = slice[a..].find("</cpe>") {
                    m.cpe.push(slice[a..a + b].to_string());
                    cs = a + b;
                } else {
                    break;
                }
            }
            host.os_matches.push(m);
        }
        s = end;
    }
}

fn parse_scripts(xml: &str) -> Vec<Script> {
    let mut out = Vec::new();
    let mut s = 0;
    while let Some(rel) = xml[s..].find("<script") {
        let start = s + rel;
        if !xml[start..].starts_with("<script ") && !xml[start..].starts_with("<script>") {
            s = start + 7;
            continue;
        }
        if let Some(tag) = tag_from(xml, start) {
            out.push(Script {
                id: attr(&tag, "id").unwrap_or_default(),
                output: unescape(&attr(&tag, "output").unwrap_or_default()),
            });
            s = start + tag.len();
        } else {
            break;
        }
    }
    out
}

fn inner_block<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let start = xml.find(&open)?;
    let after = start + xml[start..].find('>')? + 1;
    let end = xml[after..].find(&close)? + after;
    Some(&xml[after..end])
}

fn tag_attrs<'a>(xml: &'a str, name: &str) -> Option<String> {
    let needle = format!("<{name}");
    let start = xml.find(&needle)?;
    if !is_tag_name(xml, start, name) {
        return None;
    }
    tag_from(xml, start)
}

fn attr_in(xml: &str, name: &str, key: &str) -> Option<String> {
    tag_attrs(xml, name).and_then(|t| attr(&t, key))
}

fn is_tag_name(xml: &str, start: usize, name: &str) -> bool {
    let rest = &xml[start + 1 + name.len()..];
    rest.starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/')
}

fn tag_from(xml: &str, start: usize) -> Option<String> {
    let mut in_quote: Option<char> = None;
    let bytes = xml[start..].char_indices();
    for (i, c) in bytes {
        match c {
            q @ ('"' | '\'') => {
                in_quote = match in_quote {
                    Some(p) if p == q => None,
                    None => Some(q),
                    other => other,
                };
            }
            '>' if in_quote.is_none() => {
                return Some(xml[start..=start + i].to_string());
            }
            _ => {}
        }
    }
    None
}

fn attr(tag: &str, key: &str) -> Option<String> {
    let patterns = [format!("{key}=\""), format!("{key}='")];
    for p in &patterns {
        if let Some(i) = tag.find(p) {
            let q = p.chars().last()?;
            let rest = &tag[i + p.len()..];
            let end = rest.find(q)?;
            return Some(unescape(&rest[..end]));
        }
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -T4 -A -p 1-1000 scanme.nmap.org" start="1315618421" startstr="Fri Sep 9 18:33:41 2011" version="7.95" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<host starttime="1315618421" endtime="1315618435">
<status state="up" reason="echo-reply"/>
<address addr="74.207.244.221" addrtype="ipv4"/>
<hostnames>
<hostname name="scanme.nmap.org" type="user"/>
</hostnames>
<ports>
<extraports state="closed" count="995"/>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="5.3p1" method="probed" conf="10"/>
<script id="ssh-hostkey" output="1024 ab:cd (DSA)"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.2.14"/>
</port>
</ports>
<os>
<osmatch name="Linux 2.6.39" accuracy="100">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="100">
<cpe>cpe:/o:linux:linux_kernel:2.6.39</cpe>
</osclass>
</osmatch>
</os>
<trace>
<hop ttl="11" ipaddr="74.207.244.221" rtt="17.65" host="scanme.nmap.org"/>
</trace>
</host>
<runstats><finished time="1315618435" timestr="Fri Sep 9 18:33:55 2011" elapsed="14.40" summary="Nmap done" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"#;

    #[test]
    fn parses_scanme() {
        let doc = parse_document(SAMPLE).unwrap();
        assert_eq!(doc.hosts.len(), 1);
        let h = &doc.hosts[0];
        assert_eq!(h.primary_ip(), "74.207.244.221");
        assert_eq!(h.hostname(), "scanme.nmap.org");
        assert_eq!(h.ports.len(), 2);
        assert_eq!(h.ports[0].service, "ssh");
        assert_eq!(h.ports[0].scripts[0].id, "ssh-hostkey");
        assert_eq!(h.os_guess(), "Linux 2.6.39");
        assert_eq!(h.hops.len(), 1);
        assert_eq!(doc.finished.as_ref().unwrap().elapsed, "14.40");
        assert!(!doc.truncated);
    }

    #[test]
    fn ignores_truncated_host_and_hostname_tags() {
        let xml = format!(
            "{}\n<host starttime=\"1\">\n<status state=\"up\"/>\n<hostname name=\"nope\"/>\n<address addr=\"10.0.0.9\"",
            SAMPLE.replace("</nmaprun>", "")
        );
        let doc = parse_partial(&xml);
        assert_eq!(doc.hosts.len(), 1);
        assert_eq!(doc.hosts[0].primary_ip(), "74.207.244.221");
        assert!(doc.truncated);
    }

    #[test]
    fn merge_updates_same_ip() {
        let mut a = parse_partial(SAMPLE);
        let extra = SAMPLE.replace("74.207.244.221", "10.0.0.1");
        a.merge_partial(parse_partial(&extra));
        assert_eq!(a.hosts.len(), 2);
    }
}
