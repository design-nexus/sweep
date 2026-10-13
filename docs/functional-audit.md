# Sweep functional audit — 2026-10-13

## Fixed in this audit

- History resume selects `scan.nmap` instead of XML, preserves original targets/options for privilege detection, and invokes Nmap with exactly `--resume <file>`.
- Resume reuses the scan directory, XML output path, identity, start time, and original arguments instead of injecting incompatible output/progress flags. Editing scan options clears resume mode.
- Connect scans combined with OS detection or UDP correctly require privilege; pure TCP connect remains unprivileged.
- History deletion only accepts a direct owned scan directory, rejects symlinks and external paths, retains the history entry on deletion failure, and reports persistence failures.
- Profile lists use available pane height rather than a fixed five-item cap and keep keyboard selection visible.

## Verification

- 35 automated tests pass, with one interactive visual preview ignored.
- Mock scanner tests cover normal output parsing and resume argument/output preservation, including paths containing spaces. No target scan was executed.
- Owned-directory deletion tests use temporary directories and verify outside data survives rejected paths.
- Responsive rendering covers 120×40, 100×30, 80×24, 60×20, and minimum sizes; command preview, input precedence, Unicode, focus, footer styling, and profile navigation have regression coverage.
- Installed Nmap version is 7.991. Resume behavior was checked against the official Nmap output documentation: https://nmap.org/book/man-output.html.

- Release binary installed to `~/.local/bin/sweep` and verified byte-for-byte against the build. Installed PTY checks pass at 120×40, 100×30, 80×24, and 60×20: action palette, resizing, exit, termios restoration, and alternate-screen restoration.

## Remaining validation limits

- Real target scanning, privileged sudo execution, and process-tree cancellation under sudo were not exercised. Tests use mocked backends.
- Custom command parsing is not a complete Nmap option grammar; arbitrary extra options with separate values deserve review after importing a command.
- Resume verification covers managed scan history. External output basenames and missing/corrupt metadata were not exhaustively tested.
- XML import intentionally tolerates incomplete scans; it cannot reconstruct a truncated host record.

Shared navigation and additional UI checks: [navigation](navigation.md).
