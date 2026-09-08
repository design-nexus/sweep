#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    Header,
    Bool,
    Text,
    TcpScan,
    Dns,
}

pub struct FormRow {
    pub kind: RowKind,
    pub id: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
}

pub const ROWS: &[FormRow] = &[
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Target files",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "input_list",
        label: "-iL input list",
        hint: "path to hosts file",
    },
    FormRow {
        kind: RowKind::Text,
        id: "exclude",
        label: "--exclude",
        hint: "hosts/networks to skip",
    },
    FormRow {
        kind: RowKind::Text,
        id: "exclude_file",
        label: "--excludefile",
        hint: "path",
    },
    FormRow {
        kind: RowKind::Text,
        id: "random_targets",
        label: "-iR random",
        hint: "count of random IPs",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Host discovery",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "list_scan",
        label: "-sL list scan",
        hint: "list targets only",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "ping_scan",
        label: "-sn ping scan",
        hint: "no port scan",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "skip_ping",
        label: "-Pn skip ping",
        hint: "treat all hosts as up",
    },
    FormRow {
        kind: RowKind::Text,
        id: "syn_ping",
        label: "-PS SYN ping",
        hint: "ports, empty = default",
    },
    FormRow {
        kind: RowKind::Text,
        id: "ack_ping",
        label: "-PA ACK ping",
        hint: "ports",
    },
    FormRow {
        kind: RowKind::Text,
        id: "udp_ping",
        label: "-PU UDP ping",
        hint: "ports",
    },
    FormRow {
        kind: RowKind::Text,
        id: "sctp_ping",
        label: "-PY SCTP ping",
        hint: "ports",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "icmp_echo",
        label: "-PE ICMP echo",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "icmp_timestamp",
        label: "-PP ICMP timestamp",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "icmp_netmask",
        label: "-PM ICMP netmask",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "ip_proto_ping",
        label: "-PO IP proto ping",
        hint: "protocol numbers",
    },
    FormRow {
        kind: RowKind::Dns,
        id: "dns",
        label: "DNS (-n / -R)",
        hint: "space to cycle",
    },
    FormRow {
        kind: RowKind::Text,
        id: "dns_servers",
        label: "--dns-servers",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "traceroute",
        label: "--traceroute",
        hint: "",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Scan technique",
        hint: "",
    },
    FormRow {
        kind: RowKind::TcpScan,
        id: "tcp_scan",
        label: "TCP scan type",
        hint: "space to cycle",
    },
    FormRow {
        kind: RowKind::Text,
        id: "idle_zombie",
        label: "-sI zombie",
        hint: "host[:probeport]",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "udp_scan",
        label: "-sU UDP scan",
        hint: "requires root",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "sctp_init",
        label: "-sY SCTP INIT",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "sctp_cookie",
        label: "-sZ SCTP COOKIE",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "ip_proto_scan",
        label: "-sO IP protocol",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "ftp_bounce",
        label: "-b FTP bounce",
        hint: "ftp host",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Ports",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "ports",
        label: "-p ports",
        hint: "22,80,443 or 1-65535",
    },
    FormRow {
        kind: RowKind::Text,
        id: "exclude_ports",
        label: "--exclude-ports",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "fast_ports",
        label: "-F fast (top 100)",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "consecutive_ports",
        label: "-r consecutive",
        hint: "do not randomize",
    },
    FormRow {
        kind: RowKind::Text,
        id: "top_ports",
        label: "--top-ports",
        hint: "N",
    },
    FormRow {
        kind: RowKind::Text,
        id: "port_ratio",
        label: "--port-ratio",
        hint: "0-1",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Service / OS / NSE",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "version_detection",
        label: "-sV version",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "version_intensity",
        label: "--version-intensity",
        hint: "0-9",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "version_light",
        label: "--version-light",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "version_all",
        label: "--version-all",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "os_detection",
        label: "-O OS detection",
        hint: "requires root",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "osscan_limit",
        label: "--osscan-limit",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "osscan_guess",
        label: "--osscan-guess",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_os_tries",
        label: "--max-os-tries",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "default_scripts",
        label: "-sC default scripts",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "scripts",
        label: "--script",
        hint: "names or categories",
    },
    FormRow {
        kind: RowKind::Text,
        id: "script_args",
        label: "--script-args",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "script_timeout",
        label: "--script-timeout",
        hint: "e.g. 30s",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Timing",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "timing",
        label: "-T timing",
        hint: "0 paranoid … 5 insane",
    },
    FormRow {
        kind: RowKind::Text,
        id: "min_hostgroup",
        label: "--min-hostgroup",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_hostgroup",
        label: "--max-hostgroup",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "min_parallelism",
        label: "--min-parallelism",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_parallelism",
        label: "--max-parallelism",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "min_rtt_timeout",
        label: "--min-rtt-timeout",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_rtt_timeout",
        label: "--max-rtt-timeout",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "initial_rtt_timeout",
        label: "--initial-rtt-timeout",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_retries",
        label: "--max-retries",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "host_timeout",
        label: "--host-timeout",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "scan_delay",
        label: "--scan-delay",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_scan_delay",
        label: "--max-scan-delay",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "min_rate",
        label: "--min-rate",
        hint: "packets/sec",
    },
    FormRow {
        kind: RowKind::Text,
        id: "max_rate",
        label: "--max-rate",
        hint: "packets/sec",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Evasion",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "fragment",
        label: "-f fragment",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "mtu",
        label: "--mtu",
        hint: "multiple of 8",
    },
    FormRow {
        kind: RowKind::Text,
        id: "decoys",
        label: "-D decoys",
        hint: "RND:10 or ME,ip",
    },
    FormRow {
        kind: RowKind::Text,
        id: "spoof_ip",
        label: "-S spoof IP",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "interface",
        label: "-e interface",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "source_port",
        label: "-g source port",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "proxies",
        label: "--proxies",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "data_length",
        label: "--data-length",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "ttl",
        label: "--ttl",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "randomize_hosts",
        label: "--randomize-hosts",
        hint: "",
    },
    FormRow {
        kind: RowKind::Text,
        id: "spoof_mac",
        label: "--spoof-mac",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "badsum",
        label: "--badsum",
        hint: "",
    },
    FormRow {
        kind: RowKind::Header,
        id: "",
        label: "Output / misc",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "ipv6",
        label: "-6 IPv6",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "aggressive",
        label: "-A aggressive",
        hint: "-O -sV -sC --traceroute",
    },
    FormRow {
        kind: RowKind::Text,
        id: "verbose",
        label: "-v verbose",
        hint: "count",
    },
    FormRow {
        kind: RowKind::Text,
        id: "debug",
        label: "-d debug",
        hint: "count",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "reason",
        label: "--reason",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "open_only",
        label: "--open",
        hint: "only open ports",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "packet_trace",
        label: "--packet-trace",
        hint: "",
    },
    FormRow {
        kind: RowKind::Bool,
        id: "unprivileged",
        label: "--unprivileged",
        hint: "force connect scan",
    },
    FormRow {
        kind: RowKind::Text,
        id: "extra",
        label: "extra args",
        hint: "appended last, not shelled",
    },
];

pub fn first_selectable() -> usize {
    ROWS.iter()
        .position(|r| r.kind != RowKind::Header)
        .unwrap_or(0)
}

pub fn next_selectable(from: usize, dir: isize) -> usize {
    let mut i = from as isize;
    for _ in 0..ROWS.len() {
        i += dir;
        if i < 0 {
            i = ROWS.len() as isize - 1;
        }
        if i >= ROWS.len() as isize {
            i = 0;
        }
        if ROWS[i as usize].kind != RowKind::Header {
            return i as usize;
        }
    }
    from
}
