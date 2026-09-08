#!/bin/sh
# Nexus-Map installer.
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/kensmith77/Nexus-Map/main/install.sh | sh
set -eu

REPO="${NEXUS_MAP_REPO:-https://github.com/kensmith77/Nexus-Map}"
BIN_NAME="nexus-map"
NEED_RUST_MAJOR=1
NEED_RUST_MINOR=85

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

ensure_path_cargo() {
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  PATH="$HOME/.cargo/bin:$PATH"
  export PATH
}

rustc_ok() {
  have rustc || return 1
  ver=$(rustc -V 2>/dev/null | awk '{print $2}' | cut -d. -f1,2)
  major=${ver%%.*}
  minor=${ver#*.}
  minor=${minor%%.*}
  [ "${major:-0}" -gt "$NEED_RUST_MAJOR" ] && return 0
  [ "${major:-0}" -eq "$NEED_RUST_MAJOR" ] && [ "${minor:-0}" -ge "$NEED_RUST_MINOR" ]
}

ensure_build_deps() {
  if rustc_ok && have cargo && have git; then
    return 0
  fi
  say "Installing Rust toolchain (rustup)…"
  if ! have curl; then
    err "curl is required to install rustup"
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  ensure_path_cargo
  rustc_ok || err "rustc $NEED_RUST_MAJOR.$NEED_RUST_MINOR+ is required (edition 2024)"
  have cargo || err "cargo not found after rustup install"
  have git || err "git is required (install git, then re-run)"
}

install_from_git() {
  say "Building Nexus-Map from $REPO (this compiles nmap's TUI; first run takes a few minutes)…"
  cargo install --git "$REPO" --locked --force "$BIN_NAME"
}

warn_nmap() {
  if have nmap; then
    say "nmap: $(nmap -V 2>/dev/null | head -n1)"
  else
    say ""
    say "note: nmap is not on PATH. Nexus-Map can open XML without it."
    say "      scanning needs nmap, e.g.  sudo apt install nmap"
  fi
}

main() {
  ensure_path_cargo
  ensure_build_deps
  install_from_git
  warn_nmap
  dest=$(command -v "$BIN_NAME" || true)
  say ""
  say "Installed: ${dest:-$HOME/.cargo/bin/$BIN_NAME}"
  say "Run:       $BIN_NAME"
  say ""
  case ":$PATH:" in
    *":$HOME/.cargo/bin:"*) ;;
    *)
      say "Add cargo to PATH for this shell:"
      say "  . \"\$HOME/.cargo/env\""
      ;;
  esac
}

main
