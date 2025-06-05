# Linux Forensics Scan Script

**Version:** 0.1 (extended)

## Overview
This script performs a comprehensive set of Linux/Unix forensic checks, organizes results into directories, and generates both section-specific HTML reports and a master report. It supports additional export formats (JSON, CSV, TAR, ZIP) and an executive HTML summary. This is the sum of my experience in Linux Forensic domain, and is intended to provide a dipstick view of things that could be checked during a quick/ rapid analysis. It is very modular, and you can add your checks easily.

Released under Apache License 2.0 license for now.

## Features
- Modular checks divided into sections:
  1. **Kernel & Modules**
  2. **/proc & Process Artifacts**
  3. **Filesystem Integrity & Attributes**
  4. **Network Indicators**
  5. **User Accounts & Authentication**
  6. **System Logs & Audit Trails**
  7. **Live Memory & Disk Forensics** (disabled by default)
  8. **CLI & DFIR Tools**
  9. **Container & VM Indicators**
  10. **Persistence & Backdoor Evidence**
  11. **Indicator & Timeline Correlation**

- Generates per-section HTML reports with:
  - A table of techniques and raw output files
  - Inline raw output with MITRE ATT&CK framework
- Generates a master `index.html` with:
  - System information (Hostname, OS, IP addresses)
  - Summary table of total, successful, skipped, and failed checks (overall and by section)
- Supports export flags:
  - `--csv` → `report_summary.csv` (with columns: Section, Technique, TTP, Command, Status)
  - `--json` → `report_summary.json` (array of JSON objects for each check)
  - `--tar` → archives the entire output directory as `.tar.gz`
  - `--zip` → archives the entire output directory as `.zip`
- Supports an **Executive HTML Summary** (`--report`) with:
  - High-level overview and overall statistics
  - Per-section summary (total, OK, skipped, failed)
  - Section-specific findings (e.g., number of hidden modules, open files, etc.)
  - Lists of notable failures and skipped checks

## Requirements
- Bash 4+
- Standard Unix utilities (`lsmod`, `cat`, `find`, `netstat`, `lsof`, `journalctl`, etc.)
- Root privileges for certain checks (warnings shown if not run as root)

## Usage

```bash
chmod +x Lin.sh
./Lin.sh [--all | <section> ...] [--json] [--csv] [--tar] [--zip] [--report]
```

- `--all` : Run all sections (kernel, proc, fs, network, users, logs, live, dfir, container, persistence, timeline)
- `<section>` : Specify one or more sections by name (e.g. `kernel fs users`)
- `--json` : Generate `report_summary.json` with results
- `--csv`  : Generate `report_summary.csv` with results
- `--tar`  : Create `<output_dir>.tar.gz`
- `--zip`  : Create `<output_dir>.zip`
- `--report` : Create `executive_summary.html` with a high-level summary

### Examples

1. Run all checks and produce an executive summary:
   ```bash
   ./Lin.sh --all --report
   ```

2. Run only kernel, filesystem, and user account checks, output CSV and ZIP archive:
   ```bash
   ./Lin.sh kernel fs users --csv --zip
   ```

3. Run process and log checks, output JSON, ZIP, and executive summary:
   ```bash
   ./Lin.sh proc logs --json --zip --report
   ```

## Output Structure
```
forensics_output_<TIMESTAMP>/
├── system_info.txt
├── report_summary.csv      (if --csv)
├── report_summary.json     (if --json)
├── executive_summary.html  (if --report)
├── index.html
├── 01_kernel_modules/
│   ├── index.html
│   ├── 01_List_loaded_kernel_modules.txt
│   ├── ...
│   └── 05_Check_for_eBPF_tracing_hooks.txt
├── 02_proc_artifacts/
│   ├── index.html
│   ├── 01_Processes_running_deleted_binaries.txt
│   ├── 02_List_open_files.txt
│   └── 03_Active_TCP_connections.txt
├── 03_filesystem_checks/
│   ├── index.html
│   ├── 01_SUID_SGID_files.txt
│   ├── 02_Recently_modified_files_last_24h.txt
│   └── 03_Disk_usage.txt
└── ... (other sections)
```

## Customization
- To enable **live memory dumps** or **disk imaging**, edit the `live_checks` section in `Lin.sh` and uncomment the relevant lines (requires proper tools and root permissions).
- All paths that write to the output directory use the `__ROOTDIR__` placeholder internally—no need to modify that unless reorganizing.

## Troubleshooting
- If you see `Utility <name> not found. Skipping this check.`, install or configure that utility, or ignore if not relevant.
- If the script reports fewer checks than expected, verify your check-list variables (`kernel_checks`, `proc_checks`, etc.) still contain all lines.

---