use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsMode {
    #[default]
    Default,
    Never,
    Always,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpScan {
    #[default]
    Default,
    Syn,
    Connect,
    Ack,
    Window,
    Maimon,
    Null,
    Fin,
    Xmas,
    Idle,
}

impl TcpScan {
    pub fn as_flag(self) -> Option<&'static str> {
        match self {
            TcpScan::Default => None,
            TcpScan::Syn => Some("-sS"),
            TcpScan::Connect => Some("-sT"),
            TcpScan::Ack => Some("-sA"),
            TcpScan::Window => Some("-sW"),
            TcpScan::Maimon => Some("-sM"),
            TcpScan::Null => Some("-sN"),
            TcpScan::Fin => Some("-sF"),
            TcpScan::Xmas => Some("-sX"),
            TcpScan::Idle => Some("-sI"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TcpScan::Default => "default",
            TcpScan::Syn => "SYN (-sS)",
            TcpScan::Connect => "connect (-sT)",
            TcpScan::Ack => "ACK (-sA)",
            TcpScan::Window => "window (-sW)",
            TcpScan::Maimon => "maimon (-sM)",
            TcpScan::Null => "null (-sN)",
            TcpScan::Fin => "FIN (-sF)",
            TcpScan::Xmas => "Xmas (-sX)",
            TcpScan::Idle => "idle (-sI)",
        }
    }

    pub fn all() -> &'static [TcpScan] {
        &[
            TcpScan::Default,
            TcpScan::Syn,
            TcpScan::Connect,
            TcpScan::Ack,
            TcpScan::Window,
            TcpScan::Maimon,
            TcpScan::Null,
            TcpScan::Fin,
            TcpScan::Xmas,
            TcpScan::Idle,
        ]
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanSpec {
    pub resume: Option<String>,
    pub targets: String,
    pub input_list: Option<String>,
    pub exclude: Option<String>,
    pub exclude_file: Option<String>,
    pub random_targets: Option<u32>,

    pub list_scan: bool,
    pub ping_scan: bool,
    pub skip_ping: bool,
    pub syn_ping: Option<String>,
    pub ack_ping: Option<String>,
    pub udp_ping: Option<String>,
    pub sctp_ping: Option<String>,
    pub icmp_echo: bool,
    pub icmp_timestamp: bool,
    pub icmp_netmask: bool,
    pub ip_proto_ping: Option<String>,
    pub dns: DnsMode,
    pub dns_servers: Option<String>,
    pub traceroute: bool,

    pub tcp_scan: TcpScan,
    pub idle_zombie: Option<String>,
    pub udp_scan: bool,
    pub sctp_init: bool,
    pub sctp_cookie: bool,
    pub ip_proto_scan: bool,
    pub ftp_bounce: Option<String>,

    pub ports: Option<String>,
    pub exclude_ports: Option<String>,
    pub fast_ports: bool,
    pub consecutive_ports: bool,
    pub top_ports: Option<u32>,
    pub port_ratio: Option<String>,

    pub version_detection: bool,
    pub version_intensity: Option<u8>,
    pub version_light: bool,
    pub version_all: bool,

    pub os_detection: bool,
    pub osscan_limit: bool,
    pub osscan_guess: bool,
    pub max_os_tries: Option<u32>,

    pub default_scripts: bool,
    pub scripts: Option<String>,
    pub script_args: Option<String>,
    pub script_timeout: Option<String>,

    pub timing: Option<u8>,
    pub min_hostgroup: Option<String>,
    pub max_hostgroup: Option<String>,
    pub min_parallelism: Option<String>,
    pub max_parallelism: Option<String>,
    pub min_rtt_timeout: Option<String>,
    pub max_rtt_timeout: Option<String>,
    pub initial_rtt_timeout: Option<String>,
    pub max_retries: Option<u32>,
    pub host_timeout: Option<String>,
    pub scan_delay: Option<String>,
    pub max_scan_delay: Option<String>,
    pub min_rate: Option<String>,
    pub max_rate: Option<String>,

    pub fragment: bool,
    pub mtu: Option<u32>,
    pub decoys: Option<String>,
    pub spoof_ip: Option<String>,
    pub interface: Option<String>,
    pub source_port: Option<String>,
    pub proxies: Option<String>,
    pub data_length: Option<u32>,
    pub ttl: Option<u8>,
    pub randomize_hosts: bool,
    pub spoof_mac: Option<String>,
    pub badsum: bool,

    pub ipv6: bool,
    pub aggressive: bool,
    pub verbose: u8,
    pub debug: u8,
    pub reason: bool,
    pub open_only: bool,
    pub packet_trace: bool,
    pub unprivileged: bool,

    pub extra: String,
}

impl ScanSpec {
    pub fn target_list(&self) -> Vec<String> {
        self.targets
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    pub fn has_targets(&self) -> bool {
        self.resume.is_some()
            || !self.target_list().is_empty()
            || self.input_list.is_some()
            || self.random_targets.is_some()
    }

    pub fn needs_root(&self) -> bool {
        if self.unprivileged {
            return false;
        }
        self.tcp_scan != TcpScan::Default && self.tcp_scan != TcpScan::Connect
            || self.udp_scan
            || self.os_detection
            || self.aggressive
            || self.icmp_echo
            || self.icmp_timestamp
            || self.icmp_netmask
            || self.sctp_init
            || self.sctp_cookie
            || self.ip_proto_scan
            || self.syn_ping.is_some()
            || self.ack_ping.is_some()
            || self.udp_ping.is_some()
    }

    /// Flags and targets, without output (`-oX` etc.) which the runner owns.
    pub fn to_argv(&self) -> Vec<String> {
        if let Some(path) = &self.resume {
            return vec!["--resume".into(), path.clone()];
        }
        let mut a = Vec::new();
        push_flag(&mut a, self.list_scan, "-sL");
        push_flag(&mut a, self.ping_scan, "-sn");
        push_flag(&mut a, self.skip_ping, "-Pn");
        push_opt(&mut a, "-PS", &self.syn_ping);
        push_opt(&mut a, "-PA", &self.ack_ping);
        push_opt(&mut a, "-PU", &self.udp_ping);
        push_opt(&mut a, "-PY", &self.sctp_ping);
        push_flag(&mut a, self.icmp_echo, "-PE");
        push_flag(&mut a, self.icmp_timestamp, "-PP");
        push_flag(&mut a, self.icmp_netmask, "-PM");
        push_opt(&mut a, "-PO", &self.ip_proto_ping);
        match self.dns {
            DnsMode::Default => {}
            DnsMode::Never => a.push("-n".into()),
            DnsMode::Always => a.push("-R".into()),
        }
        push_opt(&mut a, "--dns-servers", &self.dns_servers);
        push_flag(&mut a, self.traceroute, "--traceroute");

        if self.tcp_scan == TcpScan::Idle {
            let z = self.idle_zombie.as_deref().unwrap_or("");
            a.push("-sI".into());
            a.push(z.into());
        } else if let Some(f) = self.tcp_scan.as_flag() {
            a.push(f.into());
        }
        push_flag(&mut a, self.udp_scan, "-sU");
        push_flag(&mut a, self.sctp_init, "-sY");
        push_flag(&mut a, self.sctp_cookie, "-sZ");
        push_flag(&mut a, self.ip_proto_scan, "-sO");
        push_opt(&mut a, "-b", &self.ftp_bounce);

        push_opt(&mut a, "-p", &self.ports);
        push_opt(&mut a, "--exclude-ports", &self.exclude_ports);
        push_flag(&mut a, self.fast_ports, "-F");
        push_flag(&mut a, self.consecutive_ports, "-r");
        if let Some(n) = self.top_ports {
            a.push("--top-ports".into());
            a.push(n.to_string());
        }
        push_opt(&mut a, "--port-ratio", &self.port_ratio);

        push_flag(&mut a, self.version_detection, "-sV");
        if let Some(n) = self.version_intensity {
            a.push("--version-intensity".into());
            a.push(n.to_string());
        }
        push_flag(&mut a, self.version_light, "--version-light");
        push_flag(&mut a, self.version_all, "--version-all");

        push_flag(&mut a, self.os_detection, "-O");
        push_flag(&mut a, self.osscan_limit, "--osscan-limit");
        push_flag(&mut a, self.osscan_guess, "--osscan-guess");
        if let Some(n) = self.max_os_tries {
            a.push("--max-os-tries".into());
            a.push(n.to_string());
        }

        push_flag(&mut a, self.default_scripts, "-sC");
        push_opt(&mut a, "--script", &self.scripts);
        push_opt(&mut a, "--script-args", &self.script_args);
        push_opt(&mut a, "--script-timeout", &self.script_timeout);

        if let Some(t) = self.timing {
            a.push(format!("-T{t}"));
        }
        push_opt(&mut a, "--min-hostgroup", &self.min_hostgroup);
        push_opt(&mut a, "--max-hostgroup", &self.max_hostgroup);
        push_opt(&mut a, "--min-parallelism", &self.min_parallelism);
        push_opt(&mut a, "--max-parallelism", &self.max_parallelism);
        push_opt(&mut a, "--min-rtt-timeout", &self.min_rtt_timeout);
        push_opt(&mut a, "--max-rtt-timeout", &self.max_rtt_timeout);
        push_opt(&mut a, "--initial-rtt-timeout", &self.initial_rtt_timeout);
        if let Some(n) = self.max_retries {
            a.push("--max-retries".into());
            a.push(n.to_string());
        }
        push_opt(&mut a, "--host-timeout", &self.host_timeout);
        push_opt(&mut a, "--scan-delay", &self.scan_delay);
        push_opt(&mut a, "--max-scan-delay", &self.max_scan_delay);
        push_opt(&mut a, "--min-rate", &self.min_rate);
        push_opt(&mut a, "--max-rate", &self.max_rate);

        push_flag(&mut a, self.fragment, "-f");
        if let Some(n) = self.mtu {
            a.push("--mtu".into());
            a.push(n.to_string());
        }
        push_opt(&mut a, "-D", &self.decoys);
        push_opt(&mut a, "-S", &self.spoof_ip);
        push_opt(&mut a, "-e", &self.interface);
        push_opt(&mut a, "-g", &self.source_port);
        push_opt(&mut a, "--proxies", &self.proxies);
        if let Some(n) = self.data_length {
            a.push("--data-length".into());
            a.push(n.to_string());
        }
        if let Some(n) = self.ttl {
            a.push("--ttl".into());
            a.push(n.to_string());
        }
        push_flag(&mut a, self.randomize_hosts, "--randomize-hosts");
        push_opt(&mut a, "--spoof-mac", &self.spoof_mac);
        push_flag(&mut a, self.badsum, "--badsum");

        push_flag(&mut a, self.ipv6, "-6");
        push_flag(&mut a, self.aggressive, "-A");
        for _ in 0..self.verbose {
            a.push("-v".into());
        }
        for _ in 0..self.debug {
            a.push("-d".into());
        }
        push_flag(&mut a, self.reason, "--reason");
        push_flag(&mut a, self.open_only, "--open");
        push_flag(&mut a, self.packet_trace, "--packet-trace");
        push_flag(&mut a, self.unprivileged, "--unprivileged");

        push_opt(&mut a, "-iL", &self.input_list);
        push_opt(&mut a, "--exclude", &self.exclude);
        push_opt(&mut a, "--excludefile", &self.exclude_file);
        if let Some(n) = self.random_targets {
            a.push("-iR".into());
            a.push(n.to_string());
        }

        if !self.extra.trim().is_empty() {
            a.extend(split_argv(&self.extra));
        }
        a.extend(self.target_list());
        a
    }

    pub fn preview_command(&self) -> String {
        let mut parts = vec!["nmap".to_string()];
        parts.extend(self.to_argv());
        join_preview(&parts)
    }

    pub fn from_argv(args: &[String]) -> Self {
        let mut spec = ScanSpec::default();
        let mut i = 0;
        let skip = args
            .first()
            .is_some_and(|s| s == "nmap" || s.ends_with("/nmap"));
        if skip {
            i = 1;
        }
        let mut targets = Vec::new();
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == "--" {
                i += 1;
                continue;
            }
            if !arg.starts_with('-') {
                targets.push(arg.to_string());
                i += 1;
                continue;
            }
            if eat_flag(&mut spec.list_scan, arg, "-sL")
                || eat_flag(&mut spec.ping_scan, arg, "-sn")
                || eat_flag(&mut spec.skip_ping, arg, "-Pn")
                || eat_flag(&mut spec.icmp_echo, arg, "-PE")
                || eat_flag(&mut spec.icmp_timestamp, arg, "-PP")
                || eat_flag(&mut spec.icmp_netmask, arg, "-PM")
                || eat_flag(&mut spec.traceroute, arg, "--traceroute")
                || eat_flag(&mut spec.udp_scan, arg, "-sU")
                || eat_flag(&mut spec.sctp_init, arg, "-sY")
                || eat_flag(&mut spec.sctp_cookie, arg, "-sZ")
                || eat_flag(&mut spec.ip_proto_scan, arg, "-sO")
                || eat_flag(&mut spec.fast_ports, arg, "-F")
                || eat_flag(&mut spec.consecutive_ports, arg, "-r")
                || eat_flag(&mut spec.version_detection, arg, "-sV")
                || eat_flag(&mut spec.version_light, arg, "--version-light")
                || eat_flag(&mut spec.version_all, arg, "--version-all")
                || eat_flag(&mut spec.os_detection, arg, "-O")
                || eat_flag(&mut spec.osscan_limit, arg, "--osscan-limit")
                || eat_flag(&mut spec.osscan_guess, arg, "--osscan-guess")
                || eat_flag(&mut spec.default_scripts, arg, "-sC")
                || eat_flag(&mut spec.fragment, arg, "-f")
                || eat_flag(&mut spec.randomize_hosts, arg, "--randomize-hosts")
                || eat_flag(&mut spec.badsum, arg, "--badsum")
                || eat_flag(&mut spec.ipv6, arg, "-6")
                || eat_flag(&mut spec.aggressive, arg, "-A")
                || eat_flag(&mut spec.reason, arg, "--reason")
                || eat_flag(&mut spec.open_only, arg, "--open")
                || eat_flag(&mut spec.packet_trace, arg, "--packet-trace")
                || eat_flag(&mut spec.unprivileged, arg, "--unprivileged")
            {
                i += 1;
                continue;
            }
            match arg {
                "-v" | "--verbose" => spec.verbose = spec.verbose.saturating_add(1),
                "-d" | "--debug" => spec.debug = spec.debug.saturating_add(1),
                "-n" => spec.dns = DnsMode::Never,
                "-R" => spec.dns = DnsMode::Always,
                "-sS" => spec.tcp_scan = TcpScan::Syn,
                "-sT" => spec.tcp_scan = TcpScan::Connect,
                "-sA" => spec.tcp_scan = TcpScan::Ack,
                "-sW" => spec.tcp_scan = TcpScan::Window,
                "-sM" => spec.tcp_scan = TcpScan::Maimon,
                "-sN" => spec.tcp_scan = TcpScan::Null,
                "-sF" => spec.tcp_scan = TcpScan::Fin,
                "-sX" => spec.tcp_scan = TcpScan::Xmas,
                _ => {
                    if let Some(t) = arg.strip_prefix("-T") {
                        if t.len() == 1 && t.as_bytes()[0].is_ascii_digit() {
                            spec.timing = t.parse().ok();
                            i += 1;
                            continue;
                        }
                    }
                    if eat_opt(&mut spec.syn_ping, args, &mut i, "-PS")
                        || eat_opt(&mut spec.ack_ping, args, &mut i, "-PA")
                        || eat_opt(&mut spec.udp_ping, args, &mut i, "-PU")
                        || eat_opt(&mut spec.sctp_ping, args, &mut i, "-PY")
                        || eat_opt(&mut spec.ip_proto_ping, args, &mut i, "-PO")
                        || eat_opt(&mut spec.dns_servers, args, &mut i, "--dns-servers")
                        || eat_opt(&mut spec.ftp_bounce, args, &mut i, "-b")
                        || eat_opt(&mut spec.ports, args, &mut i, "-p")
                        || eat_opt(&mut spec.exclude_ports, args, &mut i, "--exclude-ports")
                        || eat_opt(&mut spec.port_ratio, args, &mut i, "--port-ratio")
                        || eat_opt(&mut spec.scripts, args, &mut i, "--script")
                        || eat_opt(&mut spec.script_args, args, &mut i, "--script-args")
                        || eat_opt(&mut spec.script_timeout, args, &mut i, "--script-timeout")
                        || eat_opt(&mut spec.min_hostgroup, args, &mut i, "--min-hostgroup")
                        || eat_opt(&mut spec.max_hostgroup, args, &mut i, "--max-hostgroup")
                        || eat_opt(&mut spec.min_parallelism, args, &mut i, "--min-parallelism")
                        || eat_opt(&mut spec.max_parallelism, args, &mut i, "--max-parallelism")
                        || eat_opt(&mut spec.min_rtt_timeout, args, &mut i, "--min-rtt-timeout")
                        || eat_opt(&mut spec.max_rtt_timeout, args, &mut i, "--max-rtt-timeout")
                        || eat_opt(
                            &mut spec.initial_rtt_timeout,
                            args,
                            &mut i,
                            "--initial-rtt-timeout",
                        )
                        || eat_opt(&mut spec.host_timeout, args, &mut i, "--host-timeout")
                        || eat_opt(&mut spec.scan_delay, args, &mut i, "--scan-delay")
                        || eat_opt(&mut spec.max_scan_delay, args, &mut i, "--max-scan-delay")
                        || eat_opt(&mut spec.min_rate, args, &mut i, "--min-rate")
                        || eat_opt(&mut spec.max_rate, args, &mut i, "--max-rate")
                        || eat_opt(&mut spec.decoys, args, &mut i, "-D")
                        || eat_opt(&mut spec.spoof_ip, args, &mut i, "-S")
                        || eat_opt(&mut spec.interface, args, &mut i, "-e")
                        || eat_opt(&mut spec.source_port, args, &mut i, "-g")
                        || eat_opt(&mut spec.source_port, args, &mut i, "--source-port")
                        || eat_opt(&mut spec.proxies, args, &mut i, "--proxies")
                        || eat_opt(&mut spec.spoof_mac, args, &mut i, "--spoof-mac")
                        || eat_opt(&mut spec.input_list, args, &mut i, "-iL")
                        || eat_opt(&mut spec.exclude, args, &mut i, "--exclude")
                        || eat_opt(&mut spec.exclude_file, args, &mut i, "--excludefile")
                    {
                        continue;
                    }
                    if arg == "-sI" {
                        spec.tcp_scan = TcpScan::Idle;
                        spec.idle_zombie = take_val(args, &mut i);
                        continue;
                    }
                    if arg == "--top-ports" {
                        spec.top_ports = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--version-intensity" {
                        spec.version_intensity =
                            take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--max-os-tries" {
                        spec.max_os_tries = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--max-retries" {
                        spec.max_retries = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--mtu" {
                        spec.mtu = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--data-length" {
                        spec.data_length = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--ttl" {
                        spec.ttl = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "-iR" {
                        spec.random_targets = take_val(args, &mut i).and_then(|s| s.parse().ok());
                        continue;
                    }
                    if arg == "--resume" {
                        spec.resume = take_val(args, &mut i);
                        continue;
                    }
                    // skip runner-owned output flags
                    if matches!(arg, "-oX" | "-oN" | "-oG" | "-oA" | "-oS" | "--stats-every") {
                        let _ = take_val(args, &mut i);
                        continue;
                    }
                    spec.extra = if spec.extra.is_empty() {
                        arg.to_string()
                    } else {
                        format!("{} {arg}", spec.extra)
                    };
                }
            }
            i += 1;
        }
        spec.targets = targets.join(" ");
        spec
    }

    pub fn get_bool(&self, id: &str) -> bool {
        match id {
            "list_scan" => self.list_scan,
            "ping_scan" => self.ping_scan,
            "skip_ping" => self.skip_ping,
            "icmp_echo" => self.icmp_echo,
            "icmp_timestamp" => self.icmp_timestamp,
            "icmp_netmask" => self.icmp_netmask,
            "traceroute" => self.traceroute,
            "udp_scan" => self.udp_scan,
            "sctp_init" => self.sctp_init,
            "sctp_cookie" => self.sctp_cookie,
            "ip_proto_scan" => self.ip_proto_scan,
            "fast_ports" => self.fast_ports,
            "consecutive_ports" => self.consecutive_ports,
            "version_detection" => self.version_detection,
            "version_light" => self.version_light,
            "version_all" => self.version_all,
            "os_detection" => self.os_detection,
            "osscan_limit" => self.osscan_limit,
            "osscan_guess" => self.osscan_guess,
            "default_scripts" => self.default_scripts,
            "fragment" => self.fragment,
            "randomize_hosts" => self.randomize_hosts,
            "badsum" => self.badsum,
            "ipv6" => self.ipv6,
            "aggressive" => self.aggressive,
            "reason" => self.reason,
            "open_only" => self.open_only,
            "packet_trace" => self.packet_trace,
            "unprivileged" => self.unprivileged,
            _ => false,
        }
    }

    pub fn toggle_bool(&mut self, id: &str) {
        self.resume = None;
        let set = |v: &mut bool| *v = !*v;
        match id {
            "list_scan" => set(&mut self.list_scan),
            "ping_scan" => set(&mut self.ping_scan),
            "skip_ping" => set(&mut self.skip_ping),
            "icmp_echo" => set(&mut self.icmp_echo),
            "icmp_timestamp" => set(&mut self.icmp_timestamp),
            "icmp_netmask" => set(&mut self.icmp_netmask),
            "traceroute" => set(&mut self.traceroute),
            "udp_scan" => set(&mut self.udp_scan),
            "sctp_init" => set(&mut self.sctp_init),
            "sctp_cookie" => set(&mut self.sctp_cookie),
            "ip_proto_scan" => set(&mut self.ip_proto_scan),
            "fast_ports" => set(&mut self.fast_ports),
            "consecutive_ports" => set(&mut self.consecutive_ports),
            "version_detection" => set(&mut self.version_detection),
            "version_light" => set(&mut self.version_light),
            "version_all" => set(&mut self.version_all),
            "os_detection" => set(&mut self.os_detection),
            "osscan_limit" => set(&mut self.osscan_limit),
            "osscan_guess" => set(&mut self.osscan_guess),
            "default_scripts" => set(&mut self.default_scripts),
            "fragment" => set(&mut self.fragment),
            "randomize_hosts" => set(&mut self.randomize_hosts),
            "badsum" => set(&mut self.badsum),
            "ipv6" => set(&mut self.ipv6),
            "aggressive" => set(&mut self.aggressive),
            "reason" => set(&mut self.reason),
            "open_only" => set(&mut self.open_only),
            "packet_trace" => set(&mut self.packet_trace),
            "unprivileged" => set(&mut self.unprivileged),
            _ => {}
        }
    }

    pub fn get_text(&self, id: &str) -> String {
        match id {
            "targets" => self.targets.clone(),
            "input_list" => self.input_list.clone().unwrap_or_default(),
            "exclude" => self.exclude.clone().unwrap_or_default(),
            "exclude_file" => self.exclude_file.clone().unwrap_or_default(),
            "random_targets" => num(self.random_targets),
            "syn_ping" => self.syn_ping.clone().unwrap_or_default(),
            "ack_ping" => self.ack_ping.clone().unwrap_or_default(),
            "udp_ping" => self.udp_ping.clone().unwrap_or_default(),
            "sctp_ping" => self.sctp_ping.clone().unwrap_or_default(),
            "ip_proto_ping" => self.ip_proto_ping.clone().unwrap_or_default(),
            "dns_servers" => self.dns_servers.clone().unwrap_or_default(),
            "idle_zombie" => self.idle_zombie.clone().unwrap_or_default(),
            "ftp_bounce" => self.ftp_bounce.clone().unwrap_or_default(),
            "ports" => self.ports.clone().unwrap_or_default(),
            "exclude_ports" => self.exclude_ports.clone().unwrap_or_default(),
            "top_ports" => num(self.top_ports),
            "port_ratio" => self.port_ratio.clone().unwrap_or_default(),
            "version_intensity" => num(self.version_intensity),
            "max_os_tries" => num(self.max_os_tries),
            "scripts" => self.scripts.clone().unwrap_or_default(),
            "script_args" => self.script_args.clone().unwrap_or_default(),
            "script_timeout" => self.script_timeout.clone().unwrap_or_default(),
            "timing" => num(self.timing),
            "min_hostgroup" => self.min_hostgroup.clone().unwrap_or_default(),
            "max_hostgroup" => self.max_hostgroup.clone().unwrap_or_default(),
            "min_parallelism" => self.min_parallelism.clone().unwrap_or_default(),
            "max_parallelism" => self.max_parallelism.clone().unwrap_or_default(),
            "min_rtt_timeout" => self.min_rtt_timeout.clone().unwrap_or_default(),
            "max_rtt_timeout" => self.max_rtt_timeout.clone().unwrap_or_default(),
            "initial_rtt_timeout" => self.initial_rtt_timeout.clone().unwrap_or_default(),
            "max_retries" => num(self.max_retries),
            "host_timeout" => self.host_timeout.clone().unwrap_or_default(),
            "scan_delay" => self.scan_delay.clone().unwrap_or_default(),
            "max_scan_delay" => self.max_scan_delay.clone().unwrap_or_default(),
            "min_rate" => self.min_rate.clone().unwrap_or_default(),
            "max_rate" => self.max_rate.clone().unwrap_or_default(),
            "mtu" => num(self.mtu),
            "decoys" => self.decoys.clone().unwrap_or_default(),
            "spoof_ip" => self.spoof_ip.clone().unwrap_or_default(),
            "interface" => self.interface.clone().unwrap_or_default(),
            "source_port" => self.source_port.clone().unwrap_or_default(),
            "proxies" => self.proxies.clone().unwrap_or_default(),
            "data_length" => num(self.data_length),
            "ttl" => num(self.ttl),
            "spoof_mac" => self.spoof_mac.clone().unwrap_or_default(),
            "verbose" => self.verbose.to_string(),
            "debug" => self.debug.to_string(),
            "extra" => self.extra.clone(),
            _ => String::new(),
        }
    }

    pub fn set_text(&mut self, id: &str, v: String) {
        self.resume = None;
        let opt = |v: String| {
            let t = v.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        };
        match id {
            "targets" => self.targets = v,
            "input_list" => self.input_list = opt(v),
            "exclude" => self.exclude = opt(v),
            "exclude_file" => self.exclude_file = opt(v),
            "random_targets" => self.random_targets = v.trim().parse().ok(),
            "syn_ping" => self.syn_ping = opt(v),
            "ack_ping" => self.ack_ping = opt(v),
            "udp_ping" => self.udp_ping = opt(v),
            "sctp_ping" => self.sctp_ping = opt(v),
            "ip_proto_ping" => self.ip_proto_ping = opt(v),
            "dns_servers" => self.dns_servers = opt(v),
            "idle_zombie" => self.idle_zombie = opt(v),
            "ftp_bounce" => self.ftp_bounce = opt(v),
            "ports" => self.ports = opt(v),
            "exclude_ports" => self.exclude_ports = opt(v),
            "top_ports" => self.top_ports = v.trim().parse().ok(),
            "port_ratio" => self.port_ratio = opt(v),
            "version_intensity" => self.version_intensity = v.trim().parse().ok(),
            "max_os_tries" => self.max_os_tries = v.trim().parse().ok(),
            "scripts" => self.scripts = opt(v),
            "script_args" => self.script_args = opt(v),
            "script_timeout" => self.script_timeout = opt(v),
            "timing" => self.timing = v.trim().parse().ok().filter(|n| *n <= 5),
            "min_hostgroup" => self.min_hostgroup = opt(v),
            "max_hostgroup" => self.max_hostgroup = opt(v),
            "min_parallelism" => self.min_parallelism = opt(v),
            "max_parallelism" => self.max_parallelism = opt(v),
            "min_rtt_timeout" => self.min_rtt_timeout = opt(v),
            "max_rtt_timeout" => self.max_rtt_timeout = opt(v),
            "initial_rtt_timeout" => self.initial_rtt_timeout = opt(v),
            "max_retries" => self.max_retries = v.trim().parse().ok(),
            "host_timeout" => self.host_timeout = opt(v),
            "scan_delay" => self.scan_delay = opt(v),
            "max_scan_delay" => self.max_scan_delay = opt(v),
            "min_rate" => self.min_rate = opt(v),
            "max_rate" => self.max_rate = opt(v),
            "mtu" => self.mtu = v.trim().parse().ok(),
            "decoys" => self.decoys = opt(v),
            "spoof_ip" => self.spoof_ip = opt(v),
            "interface" => self.interface = opt(v),
            "source_port" => self.source_port = opt(v),
            "proxies" => self.proxies = opt(v),
            "data_length" => self.data_length = v.trim().parse().ok(),
            "ttl" => self.ttl = v.trim().parse().ok(),
            "spoof_mac" => self.spoof_mac = opt(v),
            "verbose" => self.verbose = v.trim().parse().unwrap_or(0),
            "debug" => self.debug = v.trim().parse().unwrap_or(0),
            "extra" => self.extra = v,
            _ => {}
        }
    }

    pub fn cycle_tcp_scan(&mut self) {
        self.resume = None;
        let all = TcpScan::all();
        let i = all.iter().position(|t| *t == self.tcp_scan).unwrap_or(0);
        self.tcp_scan = all[(i + 1) % all.len()];
    }

    pub fn cycle_dns(&mut self) {
        self.resume = None;
        self.dns = match self.dns {
            DnsMode::Default => DnsMode::Never,
            DnsMode::Never => DnsMode::Always,
            DnsMode::Always => DnsMode::Default,
        };
    }
}

fn num<T: ToString>(v: Option<T>) -> String {
    v.map(|n| n.to_string()).unwrap_or_default()
}

fn push_flag(a: &mut Vec<String>, on: bool, flag: &str) {
    if on {
        a.push(flag.into());
    }
}

fn push_opt(a: &mut Vec<String>, flag: &str, val: &Option<String>) {
    if let Some(v) = val {
        a.push(flag.into());
        if !v.is_empty() {
            a.push(v.clone());
        }
    }
}

fn eat_flag(slot: &mut bool, arg: &str, flag: &str) -> bool {
    if arg == flag {
        *slot = true;
        true
    } else {
        false
    }
}

fn eat_opt(slot: &mut Option<String>, args: &[String], i: &mut usize, flag: &str) -> bool {
    let arg = &args[*i];
    if let Some(rest) = arg.strip_prefix(&format!("{flag}=")) {
        *slot = Some(rest.to_string());
        *i += 1;
        return true;
    }
    // -PS80,443 glued
    if flag.starts_with("-P") && flag.len() == 3 && arg.starts_with(flag) && arg.len() > 3 {
        *slot = Some(arg[flag.len()..].to_string());
        *i += 1;
        return true;
    }
    if arg == flag {
        *slot = take_val_opt(args, i);
        return true;
    }
    false
}

fn take_val(args: &[String], i: &mut usize) -> Option<String> {
    if *i + 1 < args.len() {
        *i += 2;
        Some(args[*i - 1].clone())
    } else {
        *i += 1;
        None
    }
}

/// Optional-value flags (`-PS`, `-PY`, …): do not swallow the next token if it looks like a flag.
fn take_val_opt(args: &[String], i: &mut usize) -> Option<String> {
    if *i + 1 < args.len() {
        let next = &args[*i + 1];
        if !next.starts_with('-') {
            *i += 2;
            return Some(next.clone());
        }
    }
    *i += 1;
    Some(String::new())
}

pub fn split_argv(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match c {
            q @ ('"' | '\'') if quote == Some(q) => quote = None,
            q @ ('"' | '\'') if quote.is_none() => quote = Some(q),
            c if c.is_whitespace() && quote.is_none() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            '\\' if quote != Some('\'') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn join_preview(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            if p.chars().any(|c| c.is_whitespace()) {
                format!("\"{p}\"")
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(spec: ScanSpec) {
        let argv = spec.to_argv();
        let mut with = vec!["nmap".to_string()];
        with.extend(argv);
        let back = ScanSpec::from_argv(&with);
        assert_eq!(spec, back, "preview was {}", spec.preview_command());
    }

    #[test]
    fn resume_is_a_standalone_command_and_retains_privilege_requirements() {
        let mut spec = ScanSpec::default();
        spec.os_detection = true;
        spec.tcp_scan = TcpScan::Connect;
        assert!(spec.needs_root());
        spec.os_detection = false;
        assert!(!spec.needs_root());
        spec.resume = Some("/tmp/a scan/scan.nmap".into());
        assert!(spec.has_targets());
        assert_eq!(spec.to_argv(), vec!["--resume", "/tmp/a scan/scan.nmap"]);
        let parsed = ScanSpec::from_argv(&[
            "nmap".into(),
            "--resume".into(),
            "/tmp/a scan/scan.nmap".into(),
        ]);
        assert_eq!(parsed.resume, spec.resume);
    }
    #[test]
    fn default_is_bare_nmap() {
        let spec = ScanSpec {
            targets: "scanme.nmap.org".into(),
            ..Default::default()
        };
        assert_eq!(spec.to_argv(), vec!["scanme.nmap.org"]);
        roundtrip(spec);
    }

    #[test]
    fn intense_profile_roundtrip() {
        let spec = ScanSpec::from_argv(&split_argv("nmap -T4 -A -v scanme.nmap.org"));
        assert_eq!(spec.timing, Some(4));
        assert!(spec.aggressive);
        assert_eq!(spec.verbose, 1);
        assert_eq!(spec.targets, "scanme.nmap.org");
        roundtrip(spec);
    }

    #[test]
    fn glued_ping_and_script_quotes() {
        let spec = ScanSpec::from_argv(&split_argv(
            r#"nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script default or discovery and safe 192.168.0.0/24"#,
        ));
        assert_eq!(spec.tcp_scan, TcpScan::Syn);
        assert!(spec.udp_scan);
        assert_eq!(spec.syn_ping.as_deref(), Some("80,443"));
        assert_eq!(spec.source_port.as_deref(), Some("53"));
        assert_eq!(spec.scripts.as_deref(), Some("default"));
        // extra words after --script without quotes land as extra/targets; quoted form:
        let spec = ScanSpec::from_argv(&split_argv(
            r#"nmap --script "default or discovery and safe" 10.0.0.1"#,
        ));
        assert_eq!(
            spec.scripts.as_deref(),
            Some("default or discovery and safe")
        );
        roundtrip(spec);
    }

    #[test]
    fn extra_args_are_not_shelled() {
        let mut spec = ScanSpec::default();
        spec.extra = r#"--datadir "/tmp/my nmap" --foo"#.into();
        spec.targets = "h".into();
        let argv = spec.to_argv();
        assert!(argv.contains(&"--datadir".to_string()));
        assert!(argv.contains(&"/tmp/my nmap".to_string()));
        assert!(!argv.iter().any(|a| a.contains('`')));
    }

    #[test]
    fn syn_needs_root_connect_does_not() {
        let mut spec = ScanSpec {
            tcp_scan: TcpScan::Syn,
            ..Default::default()
        };
        assert!(spec.needs_root());
        spec.tcp_scan = TcpScan::Connect;
        assert!(!spec.needs_root());
        spec.unprivileged = true;
        spec.tcp_scan = TcpScan::Syn;
        assert!(!spec.needs_root());
    }
}
