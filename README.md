# Linux Forensics Scan Suite

A lightweight toolkit to perform native Linux/Unix compromise-detection checks. Summary of my experience in this domain, can be extended as well.

## Contents

- **linux_forensics_scan.sh**  
  Modular script that:
  - Runs predefined checks (kernel, filesystem, processes, network, etc.)
  - Captures raw output in section-specific folders
  - Generates HTML reports per section and a master index
  - Accepts multiple section names (or `--all`) in any order

- **unit_test_for_scan.sh**  
  Simple test harness that:
  - Executes each check command (skips interactive steps)
  - Detects missing utilities (including commands inside composite checks)
  - Logs status and basic output info to `unit_test_results.txt`

- **linux_forensic_techniques.md**  
  Reference table of all native and external techniques used by the scan script:
  - Technique name
  - Native vs. external utility
  - MITRE ATT&CK TTP mapping
  - Sample command  
  Consult this file to understand each check, add new techniques, or review coverage

## Requirements

- POSIX-compliant shell (`/bin/sh`)
- Standard utilities: `lsmod`, `awk`, `sort`, `diff`, `grep`, `find`, etc.
- Optional tools for certain checks:
  - `iptables`, `ss`, `lsof`, `tcpdump`
  - `rpm`/`debsums`, `lsattr`, `jq`, `bpftool`, `tracee-ebpf`
  - `chkrootkit`, `rkhunter`, `unhide`, `yara`, `strace`
- Root privileges for deeper checks (e.g., dumping memory, reading protected files)

## Usage

1. **Scan for anomalies**
   ```sh
   chmod +x linux_forensics_scan.sh
   ./linux_forensics_scan.sh --all
   # Or:
   ./linux_forensics_scan.sh kernel fs proc network

	•	Creates a timestamped forensics_output_<TIMESTAMP>/ directory
	•	Runs only specified sections (or all if --all)
	•	Produces:
	•	Raw output files (.txt) under numbered subdirectories
	•	HTML reports per section
	•	A master index.html summarizing which sections ran or were skipped

	2.	Run unit tests

chmod +x unit_test_for_scan.sh
./unit_test_for_scan.sh

	•	Generates unit_test_results.txt with one entry per check
	•	Flags missing utilities, permission errors, or successful runs

	3.	Review technique definitions

linux_forensic_techniques.md

	•	Contains a table of every technique and its associated command/TTP
	•	Helps audit or extend the script’s checks

Sections & Checks
	•	kernel: loaded modules, kernel taint, hidden modules, eBPF hooks
	•	proc: deleted-binary processes, memfd fds, deleted mappings, LD_PRELOAD, cmdline/comm mismatch
	•	fs: RPM/DEB verification, immutable files, SUID/SGID, unowned files, hidden dirs, bind-mount/iptables
	•	network: listening sockets, open-socket mapping, DNS capture, iptables rules, BPF programs
	•	users: UID 0 entries, SSH keys, sudoers, login history, failed logins, history symlinks
	•	logs: control-character in logs, audit execve, journalctl, rotated logs, cron entries
	•	live: RAM dump (AVML/LiME), optional process memory, disk image, timeline carving
	•	dfir: chkrootkit, rkhunter, unhide, ELF inspection, YARA, strace, BPF audit
	•	container: running containers, mount info, VM logs
	•	persistence: rc.local, init scripts, systemd units, root SSH keys, hidden cron
	•	timeline: uptime, last logins, journal gaps

Notes
	•	Interactive checks prompt for consent and parameters
	•	Missing utilities are skipped; HTML and console outputs note “Utility … not present”
	•	Root access is required for certain checks (e.g., iptables, /proc details, memory dumps)
	•	Consult linux_forensic_techniques.md to see exactly which commands map to which TTPs and utilities

License

Currently MIT.

