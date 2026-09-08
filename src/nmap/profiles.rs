use super::args::{ScanSpec, split_argv};

#[derive(Clone, Debug)]
pub struct Profile {
    pub name: &'static str,
    pub command: &'static str,
    pub description: &'static str,
}

pub fn builtin_profiles() -> &'static [Profile] {
    &[
        Profile {
            name: "Intense scan",
            command: "nmap -T4 -A -v",
            description: "OS detection, version detection, script scan, and traceroute.",
        },
        Profile {
            name: "Intense scan plus UDP",
            command: "nmap -sS -sU -T4 -A -v",
            description: "Intense scan plus UDP ports. Requires root.",
        },
        Profile {
            name: "Intense scan, all TCP ports",
            command: "nmap -p 1-65535 -T4 -A -v",
            description: "Intense scan of every TCP port.",
        },
        Profile {
            name: "Intense scan, no ping",
            command: "nmap -T4 -A -v -Pn",
            description: "Intense scan without host discovery.",
        },
        Profile {
            name: "Ping scan",
            command: "nmap -sn",
            description: "Discover which targets are up. No port scan.",
        },
        Profile {
            name: "Quick scan",
            command: "nmap -T4 -F",
            description: "Aggressive timing, top 100 ports.",
        },
        Profile {
            name: "Quick scan plus",
            command: "nmap -sV -T4 -O -F --version-light",
            description: "Quick scan plus OS and light version detection.",
        },
        Profile {
            name: "Quick traceroute",
            command: "nmap -sn --traceroute",
            description: "Traceroute without a port scan.",
        },
        Profile {
            name: "Regular scan",
            command: "nmap",
            description: "Nmap defaults (top 1000 TCP ports).",
        },
        Profile {
            name: "Slow comprehensive scan",
            command: r#"nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or discovery and safe""#,
            description: "TCP+UDP, extra discovery probes, default/discovery/safe scripts.",
        },
    ]
}

impl Profile {
    pub fn spec(&self) -> ScanSpec {
        ScanSpec::from_argv(&split_argv(self.command))
    }
}

pub fn by_name(name: &str) -> Option<&'static Profile> {
    builtin_profiles()
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_parses() {
        for p in builtin_profiles() {
            let spec = p.spec();
            let preview = spec.preview_command();
            assert!(preview.starts_with("nmap"), "{preview}");
            let back = ScanSpec::from_argv(&split_argv(&preview));
            assert_eq!(
                spec, back,
                "profile {} failed roundtrip:\n{preview}",
                p.name
            );
        }
    }
}
