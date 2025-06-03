#!/bin/sh
#
# linux_forensics_scan.sh v0.1
#
# Implementation of native checks in SH format. POSIX compliant wherever possible.
# organize raw outputs and HTML reports by section, and generate a master HTML index.
# Created by Rishabh Dangwal
#
# Usage:
#   ./linux_forensics_scan.sh --all
#   ./linux_forensics_scan.sh [kernel fs proc network users logs live dfir container persistence timeline]
#   (Multiple sections can be specified in any order.)
#
# Version: 0.1
# Sections:
#   kernel      : Kernel & Modules
#   proc        : /proc & Process Artifacts
#   fs          : Filesystem Integrity & Attributes
#   network     : Network Indicators
#   users       : User Accounts & Authentication
#   logs        : System Logs & Audit Trails
#   live        : Live Memory & Disk Forensics
#   dfir        : CLI & DFIR Tools
#   container   : Container & VM Indicators
#   persistence : Persistence & Backdoor Evidence
#   timeline    : Indicator & Timeline Correlation

echo "linux_forensics_scan.sh version 0.1"

###############################################################################
###  Configuration and Utility Functions
###############################################################################

# Root output directory (timestamped)
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ROOT_DIR="forensics_output_${TIMESTAMP}"

# List of all available sections (short names)
ALL_SECTIONS="kernel proc fs network users logs live dfir container persistence timeline"

# Mapping short names to display titles
display_title() {
  case "$1" in
    kernel)      echo "Kernel & Modules";;
    proc)        echo "/proc & Process Artifacts";;
    fs)          echo "Filesystem Integrity & Attributes";;
    network)     echo "Network Indicators";;
    users)       echo "User Accounts & Authentication";;
    logs)        echo "System Logs & Audit Trails";;
    live)        echo "Live Memory & Disk Forensics";;
    dfir)        echo "CLI & DFIR Tools";;
    container)   echo "Container & VM Indicators";;
    persistence) echo "Persistence & Backdoor Evidence";;
    timeline)    echo "Indicator & Timeline Correlation";;
    *)           echo "$1";;
  esac
}

# Mapping short names to directory names (with numeric prefix)
section_dir() {
  case "$1" in
    kernel)      echo "01_kernel_modules";;
    proc)        echo "02_proc_artifacts";;
    fs)          echo "03_fs_integrity";;
    network)     echo "04_network_indicators";;
    users)       echo "05_user_accounts";;
    logs)        echo "06_system_logs";;
    live)        echo "07_live_forensics";;
    dfir)        echo "08_dfir_tools";;
    container)   echo "09_container_vm";;
    persistence) echo "10_persistence";;
    timeline)    echo "11_timeline";;
    *)           echo "$1";;
  esac
}

# HTML template for section headers/footers
html_header() {
  SECTION_TITLE="$1"
  cat <<EOF > "$HTML_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${SECTION_TITLE}</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    pre { background-color: #f4f4f4; padding: 10px; overflow-x: auto; }
    code { font-family: monospace; }
    h1 { margin-bottom: 0.5em; }
    h2 { border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 1.5em; }
    p { margin: 0.5em 0; }
  </style>
</head>
<body>
  <h1>${SECTION_TITLE}</h1>
  <p><a href="../index.html">Back to report index</a></p>
EOF
}

html_footer() {
  cat <<EOF >> "$HTML_FILE"
</body>
</html>
EOF
}

# Check if a command exists; if not, set SKIP_UTIL to true
require_util() {
  UTIL_NAME="$1"
  if ! command -v "$UTIL_NAME" >/dev/null 2>&1; then
    SKIP_UTIL=1
    return 1
  fi
  SKIP_UTIL=0
  return 0
}

# Record a single check: collect raw output and append to section HTML 
run_check() {
  TECHNIQUE="$1"
  TTP="$2"
  CMD="$3"
  RAW_OUT="$4"

  # Append HTML header for this technique
  echo "<h2>Technique: ${TECHNIQUE}</h2>" >> "$HTML_FILE"
  echo "<p><strong>MITRE ATT&CK TTP:</strong> ${TTP}</p>" >> "$HTML_FILE"
  echo "<p><code>${CMD}</code></p>" >> "$HTML_FILE"
  echo "<pre>" >> "$HTML_FILE"

  # Extract primary utility: first non-whitespace token across all lines
  UTIL="$(printf "%s" "$CMD" | tr '\n' ' ' | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f1)"
  require_util "$UTIL"
  if [ "$SKIP_UTIL" -eq 1 ]; then
    # Utility missing: record and report
    echo "Utility ${UTIL} not found. Skipping this check." > "$RAW_OUT"
    echo "Utility ${UTIL} not found. Skipping this check." >> "$HTML_FILE"
    echo "Technique: ${TECHNIQUE} | MITRE ATT&CK TTP: ${TTP}"
    echo "Check performed [NO] : Utility not present"
  else
    # Execute the command, capture output
    sh -c "$CMD" > "$RAW_OUT" 2>&1
    RC=$?
    if [ $RC -ne 0 ]; then
      # Non-zero exit: record stderr and mark failure
      sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$RAW_OUT" >> "$HTML_FILE"
      echo "Technique: ${TECHNIQUE} | MITRE ATT&CK TTP: ${TTP}"
      echo "Check performed [NO] : Exit code ${RC}"
    else
      # Command succeeded (exit 0)
      sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$RAW_OUT" >> "$HTML_FILE"
      echo "Technique: ${TECHNIQUE} | MITRE ATT&CK TTP: ${TTP}"
      echo "Check performed [OK]"
    fi
  fi

  echo "</pre>" >> "$HTML_FILE"
}

###############################################################################
###  Section: Header Info
###############################################################################
print_system_info() {
  INFO_FILE="${ROOT_DIR}/system_info.txt"

  mkdir -p "$ROOT_DIR"
  {
    echo "Hostname: $(hostname)"
    echo "Date: $(date -u)"
    echo "OS Details: $(uname -a || echo \"uname not available\")"
    if command -v lsb_release >/dev/null 2>&1; then
      echo "Distributor ID: $(lsb_release -i -s)"
      echo "Release: $(lsb_release -r -s)"
      echo "Codename: $(lsb_release -c -s)"
    elif [ -f /etc/os-release ]; then
      . /etc/os-release
      echo "NAME: $NAME"
      echo "VERSION: $VERSION"
    fi
    echo "IP Addresses:"
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
      hostname -I
    elif command -v ip >/dev/null 2>&1; then
      ip -o -4 addr list | awk '{print $2": "$4}'
    else
      ifconfig 2>/dev/null | grep -E 'inet '
    fi
  } > "$INFO_FILE"
}

###############################################################################
###  Section Functions
###############################################################################

# 1. Kernel & Modules
scan_kernel_modules() {
  SECTION_NAME="Kernel & Modules"
  DIR_NAME="$(section_dir kernel)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 1.1 List loaded kernel modules
  RAW_OUT="${SECTION_DIR}/01_lsmod.txt"
  run_check "List loaded kernel modules" "T1215" "lsmod" "$RAW_OUT"

  # 1.2 Check for kernel taint
  RAW_OUT="${SECTION_DIR}/02_kernel_tainted.txt"
  run_check "Check for kernel taint" "T1215" "cat /proc/sys/kernel/tainted" "$RAW_OUT"

  # 1.3 Compare lsmod vs /sys/module
  RAW_OUT="${SECTION_DIR}/03_compare_lsmod_sys_module.txt"
  CMD='
    lsmod | tail -n +2 | awk "{print \$1}" | sort > '"${SECTION_DIR}/tmp1.lst"'
    ls /sys/module | sort > '"${SECTION_DIR}/tmp2.lst"'
    diff -u '"${SECTION_DIR}/tmp1.lst"' '"${SECTION_DIR}/tmp2.lst"'
  '
  run_check "Compare lsmod vs /sys/module" "T1215" "$CMD" "$RAW_OUT"
  rm -f "${SECTION_DIR}/tmp1.lst" "${SECTION_DIR}/tmp2.lst"

  # 1.4 Detect hidden/malicious modules via diff
  RAW_OUT="${SECTION_DIR}/04_detect_hidden_modules.txt"
  CMD='
    lsmod | tail -n +2 | awk "{print \$1}" | sort > '"${SECTION_DIR}/tmp1.lst"'
    ls /sys/kernel/tracing/available_filter_functions | sed -n "s/.*\[\([^]]*\)\].*/\1/p" | sort | uniq > '"${SECTION_DIR}/tmp2.lst"'
    diff -u '"${SECTION_DIR}/tmp1.lst"' '"${SECTION_DIR}/tmp2.lst"'
  '
  run_check "Detect hidden/malicious modules" "T1215" "$CMD" "$RAW_OUT"
  rm -f "${SECTION_DIR}/tmp1.lst" "${SECTION_DIR}/tmp2.lst"

  # 1.5 Check for eBPF / tracing hooks
  RAW_OUT="${SECTION_DIR}/05_check_tracing_hooks.txt"
  run_check "Check for eBPF / tracing hooks" "T1215" "cat /sys/kernel/debug/tracing/trace && cat /sys/kernel/debug/tracing/enabled_functions" "$RAW_OUT"

  html_footer
}

# 2. /proc & Process Artifacts
scan_proc_artifacts() {
  SECTION_NAME="/proc & Process Artifacts"
  DIR_NAME="$(section_dir proc)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 2.1 Processes running deleted binaries
  RAW_OUT="${SECTION_DIR}/01_deleted_binaries.txt"
  CMD="ls -alR /proc/*/exe 2>/dev/null | grep deleted"
  run_check "Processes running deleted binaries" "T1055" "$CMD" "$RAW_OUT"

  # 2.2 Memory-only (‘memfd’) file descriptors across all PIDs
  RAW_OUT="${SECTION_DIR}/02_memfd_fds.txt"
  CMD='
    for pid in $(ls /proc 2>/dev/null | grep "^[0-9]\+$"); do
      ls "/proc/${pid}/fd" 2>/dev/null | grep memfd && echo "PID: ${pid}"
    done
  '
  run_check "Memory-only (‘memfd’) file descriptors" "T1055" "$CMD" "$RAW_OUT"

  # 2.3 Deleted mappings in a process’s memory
  RAW_OUT="${SECTION_DIR}/03_deleted_mappings.txt"
  CMD='
    for pid in $(ls /proc 2>/dev/null | grep "^[0-9]\+$"); do
      grep "(deleted)" "/proc/${pid}/maps" 2>/dev/null && echo "PID: ${pid}"
    done
  '
  run_check "Deleted mappings in process memory" "T1055" "$CMD" "$RAW_OUT"

  # 2.4 Environment-based injection (LD_PRELOAD)
  RAW_OUT="${SECTION_DIR}/04_ld_preload_env.txt"
  CMD='
    for pid in $(ls /proc 2>/dev/null | grep "^[0-9]\+$"); do
      strings "/proc/${pid}/environ" 2>/dev/null | tr "\0" "\n" | grep LD_PRELOAD && echo "PID: ${pid}"
    done
  '
  run_check "Environment-based injection (LD_PRELOAD)" "T1574.002" "$CMD" "$RAW_OUT"

  # 2.5 Mismatched cmdline vs comm (masquerading)
  RAW_OUT="${SECTION_DIR}/05_mismatched_cmdline_comm.txt"
  CMD='
    for pid in $(ls /proc 2>/dev/null | grep "^[0-9]\+$"); do
      if [ -r "/proc/${pid}/cmdline" ] && [ -r "/proc/${pid}/comm" ]; then
        CMPL=$(tr "\0" " " < "/proc/${pid}/cmdline")
        COMM=$(cat "/proc/${pid}/comm")
        case "$CMPL" in
          *"$COMM"*) ;;
          *) echo "PID: ${pid} | cmdline: ${CMPL} | comm: ${COMM}" ;;
        esac
      fi
    done
  '
  run_check "Mismatched cmdline vs comm (masquerading)" "T1036" "$CMD" "$RAW_OUT"

  # 2.6 Working directory of daemons/processes
  RAW_OUT="${SECTION_DIR}/06_proc_cwd.txt"
  run_check "Working directory of processes" "T1036" "ls -alR /proc/*/cwd 2>/dev/null" "$RAW_OUT"

  # 2.7 Processes running from /tmp or /dev/shm
  RAW_OUT="${SECTION_DIR}/07_proc_from_tmp_dev.txt"
  run_check "Processes running from /tmp or /dev/shm" "T1036" "ls -alR /proc/*/cwd 2>/dev/null | grep \"/tmp\\|/dev/shm\"" "$RAW_OUT"

  html_footer
}

# 3. Filesystem Integrity & Attributes
scan_filesystem_integrity() {
  SECTION_NAME="Filesystem Integrity & Attributes"
  DIR_NAME="$(section_dir fs)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 3.1 Verify installed RPM files
  RAW_OUT="${SECTION_DIR}/01_rpm_verify.txt"
  run_check "Verify installed RPM files" "T1105" "rpm -Va | grep '^..5.'" "$RAW_OUT"

  # 3.2 Verify installed DEB files
  RAW_OUT="${SECTION_DIR}/02_deb_verify.txt"
  run_check "Verify installed DEB files" "T1105" "debsums -c" "$RAW_OUT"

  # 3.3 Immutable files & directories
  RAW_OUT="${SECTION_DIR}/03_lsattr.txt"
  run_check "Immutable files & directories" "T1562.003" "lsattr -R / 2>/dev/null | grep ' i '" "$RAW_OUT"

  # 3.4 Find SUID/SGID files
  RAW_OUT="${SECTION_DIR}/04_suid_sgid.txt"
  run_check "Find SUID/SGID files" "T1543" "find / -type f \\( -perm -04000 -o -perm -02000 \\) -exec ls -lg {} \\; 2>/dev/null" "$RAW_OUT"

  # 3.5 Files/dirs with no valid owner/group
  RAW_OUT="${SECTION_DIR}/05_nouser_nogroup.txt"
  run_check "Files/dirs with no valid owner/group" "T1083" "find / \\( -nouser -o -nogroup \\) -exec ls -lg {} \\; 2>/dev/null" "$RAW_OUT"

  # 3.6 Hidden files / Unexpected '.' directories
  RAW_OUT="${SECTION_DIR}/06_hidden_dirs.txt"
  run_check "Hidden files / Unexpected '.' directories" "T1083" "find / -type d -name '.*' 2>/dev/null" "$RAW_OUT"

  # 3.7 Bind-mount anomalies & iptables rules
  RAW_OUT="${SECTION_DIR}/07_bind_mounts.txt"
  CMD='iptables -L -v -n 2>/dev/null; iptables -t nat -L -v -n 2>/dev/null; cat /proc/mounts | grep proc; mount | grep -vE "(/etc|/proc|/sys|/dev)"'
  run_check "Bind-mount anomalies & iptables rules" "T1562.003" "$CMD" "$RAW_OUT"

  html_footer
}

# 4. Network Indicators
scan_network_indicators() {
  SECTION_NAME="Network Indicators"
  DIR_NAME="$(section_dir network)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 4.1 Listening sockets & owner
  RAW_OUT="${SECTION_DIR}/01_ss_plant.txt"
  run_check "Listening sockets & owner" "T1049" "ss -plant 2>/dev/null" "$RAW_OUT"

  # 4.2 Map open sockets to processes
  RAW_OUT="${SECTION_DIR}/02_lsof_network.txt"
  run_check "Map open sockets to processes" "T1049" "lsof -Pn -i 2>/dev/null" "$RAW_OUT"

  # 4.3 DNS tunneling / Unexpected DNS queries (capture 20 packets)
  RAW_OUT="${SECTION_DIR}/03_tcpdump_dns.txt"
  run_check "DNS tunneling / Unexpected DNS queries" "T1040" "tcpdump -i any -n -s0 udp port 53 -c 20" "$RAW_OUT"

  # 4.4 iptables & NAT anomalies
  RAW_OUT="${SECTION_DIR}/04_iptables_rules.txt"
  run_check "iptables rules & NAT anomalies" "T1562.003" "iptables -L -v -n 2>/dev/null; iptables -t nat -L -v -n 2>/dev/null" "$RAW_OUT"

  # 4.5 eBPF / XDP programs
  RAW_OUT="${SECTION_DIR}/05_bpftool.txt"
  CMD='ip link show | grep xdp 2>/dev/null; bpftool prog list 2>/dev/null; bpftool map list 2>/dev/null'
  run_check "eBPF / XDP programs" "T1215" "$CMD" "$RAW_OUT"

  html_footer
}

# 5. User Accounts & Authentication
scan_user_accounts() {
  SECTION_NAME="User Accounts & Authentication"
  DIR_NAME="$(section_dir users)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 5.1 Look for UID=0 entries
  RAW_OUT="${SECTION_DIR}/01_uid0_entries.txt"
  run_check "Look for UID=0 entries" "T1087" "grep '^.*:x:0:' /etc/passwd" "$RAW_OUT"

  # 5.2 Check SSH authorized_keys files
  RAW_OUT="${SECTION_DIR}/02_ssh_authorized_keys.txt"
  run_check "Check SSH authorized_keys files" "T1574.002" "find /home -name authorized_keys 2>/dev/null" "$RAW_OUT"

  # 5.3 Inspect /etc/sudoers & /etc/sudoers.d/"
  RAW_OUT="${SECTION_DIR}/03_sudoers.txt"
  CMD='cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null'
  run_check "Inspect /etc/sudoers & /etc/sudoers.d/" "T1574.002" "$CMD" "$RAW_OUT"

  # 5.4 Recent login history
  RAW_OUT="${SECTION_DIR}/04_recent_logins.txt"
  run_check "Recent login history" "T1087" "last" "$RAW_OUT"

  # 5.5 Failed login attempts
  RAW_OUT="${SECTION_DIR}/05_failed_logins.txt"
  run_check "Failed login attempts" "T1087" "lastb" "$RAW_OUT"

  # 5.6 Symlinked or missing history files
  RAW_OUT="${SECTION_DIR}/06_history_symlinks.txt"
  run_check "Symlinked or missing history files" "T1087" "find / -name '.*history' 2>/dev/null | grep null" "$RAW_OUT"

  html_footer
}

# 6. System Logs & Audit Trails
scan_system_logs() {
  SECTION_NAME="System Logs & Audit Trails"
  DIR_NAME="$(section_dir logs)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 6.1 Binary data injected into logs
  RAW_OUT="${SECTION_DIR}/01_binary_in_logs.txt"
  run_check "Binary data injected into logs" "T1005" "grep '[[:cntrl:]]' /var/log/*.log 2>/dev/null" "$RAW_OUT"

  # 6.2 Auditd execve events (if auditd/ausearch is available)
  RAW_OUT="${SECTION_DIR}/02_audit_execve.txt"
  run_check "Auditd execve events" "T1005" "ausearch -m execve -ts today 2>/dev/null" "$RAW_OUT"

  # 6.3 Inspect systemd journal
  RAW_OUT="${SECTION_DIR}/03_journalctl.txt"
  run_check "Inspect systemd journal around incident" "T1005" "journalctl -S yesterday -U now 2>/dev/null" "$RAW_OUT"

  # 6.4 Log rotation / Missing log files
  RAW_OUT="${SECTION_DIR}/04_log_rotation.txt"
  run_check "Log rotation / Missing log files" "T1005" "ls -al /var/log/*.1 /var/log/*.gz 2>/dev/null" "$RAW_OUT"

  # 6.5 Suspicious cron entries
  RAW_OUT="${SECTION_DIR}/05_cron_entries.txt"
  run_check "Suspicious cron entries" "T1053" "ls /etc/cron* /var/spool/cron/crontabs 2>/dev/null" "$RAW_OUT"

  html_footer
}

# 7. Live Memory & Disk Forensics
scan_live_forensics() {
  SECTION_NAME="Live Memory & Disk Forensics"
  DIR_NAME="$(section_dir live)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 7.1 Dump full RAM (AVML)
  RAW_OUT="${SECTION_DIR}/01_avml.txt"
  run_check "Dump full RAM (AVML)" "T1055" "avml /tmp/mem_${TIMESTAMP}.dmp" "$RAW_OUT"

  # 7.2 Dump full RAM (LiME)
  RAW_OUT="${SECTION_DIR}/02_lime.txt"
  run_check "Dump full RAM (LiME)" "T1055" "insmod lime.ko path=/tmp/mem_${TIMESTAMP}.lime format=lime" "$RAW_OUT"

  # 7.3 Process memory snapshot (interactive)
  echo "Perform process memory snapshot? (y/N)"
  read RESP_MEM
  if [ "$RESP_MEM" = "y" ] || [ "$RESP_MEM" = "Y" ]; then
    echo "Enter PID to snapshot:"
    read TARGET_PID
    RAW_OUT="${SECTION_DIR}/03_proc_${TARGET_PID}_gcore.txt"
    CMD="gcore ${TARGET_PID}"
    run_check "Process memory snapshot (PID=${TARGET_PID})" "T1055" "$CMD" "$RAW_OUT"
  else
    echo "<p>Process memory snapshot: skipped.</p>" >> "$HTML_FILE"
  fi

  # 7.4 Create disk image locally (interactive)
  echo "Create local disk image? (y/N)"
  read RESP_IMG
  if [ "$RESP_IMG" = "y" ] || [ "$RESP_IMG" = "Y" ]; then
    echo "Enter device path (e.g., /dev/sda):"
    read DEV_PATH
    RAW_OUT="${SECTION_DIR}/04_dd_${DEV_PATH##*/}.txt"
    CMD="dd if=${DEV_PATH} bs=4M of=${SECTION_DIR}/disk_image_${TIMESTAMP}.dd"
    run_check "Create disk image (device=${DEV_PATH})" "T1005" "$CMD" "$RAW_OUT"
    gzip "${SECTION_DIR}/disk_image_${TIMESTAMP}.dd" 2>/dev/null
  else
    echo "<p>Disk image creation: skipped.</p>" >> "$HTML_FILE"
  fi

  # 7.5 Carve filesystem timeline (requires TIMELINE_IMAGE environment variable)
  if [ -n "$TIMELINE_IMAGE" ] && [ -r "$TIMELINE_IMAGE" ]; then
    RAW_OUT="${SECTION_DIR}/05_timeline.txt"
    CMD='
      OFFSET=$(mmls "'"$TIMELINE_IMAGE"'" 2>/dev/null | head -n 1 | awk "{print \$1}")
      fls -o "$OFFSET" -r -m / "'"$TIMELINE_IMAGE"'" > "'"${SECTION_DIR}/fls_'${TIMESTAMP}'.txt"'"
      mactime -b "'"${SECTION_DIR}/fls_'${TIMESTAMP}'.txt"'" > "'"${SECTION_DIR}/timeline_'${TIMESTAMP}'.csv"'"
      echo "Timeline generated: timeline_'${TIMESTAMP}'.csv"
    '
    run_check "Carve filesystem timeline" "T1005" "$CMD" "$RAW_OUT"
  else
    echo "<p>No valid TIMELINE_IMAGE set or file unreadable; skipping filesystem timeline carving.</p>" >> "$HTML_FILE"
  fi

  html_footer
}

# 8. CLI & DFIR Tools
scan_dfir_tools() {
  SECTION_NAME="CLI & DFIR Tools"
  DIR_NAME="$(section_dir dfir)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 8.1 Check for known rootkits (chkrootkit)
  RAW_OUT="${SECTION_DIR}/01_chkrootkit.txt"
  run_check "Check for known rootkits (chkrootkit)" "T1215" "chkrootkit" "$RAW_OUT"

  # 8.2 Check for known rootkits (rkhunter)
  RAW_OUT="${SECTION_DIR}/02_rkhunter.txt"
  run_check "Check for known rootkits (rkhunter)" "T1215" "rkhunter --check --sk" "$RAW_OUT"

  # 8.3 Scan for hidden processes (unhide)
  RAW_OUT="${SECTION_DIR}/03_unhide.txt"
  run_check "Scan for hidden processes (unhide)" "T1057" "unhide quick" "$RAW_OUT"

  # 8.4 Static ELF inspection (readelf / strings)
  RAW_OUT="${SECTION_DIR}/04_readelf.txt"
  CMD='readelf -h /usr/bin/sshd 2>/dev/null; strings /usr/bin/sshd'
  run_check "Static ELF inspection (readelf / strings)" "T1036" "$CMD" "$RAW_OUT"

  # 8.5 YARA scanning for known patterns (yara)
  RAW_OUT="${SECTION_DIR}/05_yara.txt"
  run_check "YARA scanning for known patterns (yara)" "T1215" "yara -r /usr/local/share/yara_rules -s /usr/bin/sshd" "$RAW_OUT"

  # 8.6 Strace on suspicious process (example PID 1)
  RAW_OUT="${SECTION_DIR}/06_strace.txt"
  require_util strace
  if [ "$SKIP_UTIL" -eq 1 ]; then
    echo "Utility strace not found. Skipping this check." > "$RAW_OUT"
    echo "Technique: Strace on process | MITRE ATT&CK TTP: T1055"
    echo "Check performed [NO] : Utility not present"
    echo "Utility strace not found. Skipping this check." >> "$HTML_FILE"
  else
    strace -f -e execve -p 1 -o "${SECTION_DIR}/strace_pid1.log" 2>/dev/null
    echo "Output written to strace_pid1.log" > "$RAW_OUT"
    sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "${SECTION_DIR}/strace_pid1.log" >> "$HTML_FILE"
    echo "Technique: Strace on process | MITRE ATT&CK TTP: T1055"
    echo "Check performed [OK]"
  fi

  # 8.7 List active BPF programs (bpftool)
  RAW_OUT="${SECTION_DIR}/07_bpftool_prog.txt"
  run_check "List active BPF programs (bpftool)" "T1215" "bpftool prog list 2>/dev/null" "$RAW_OUT"

  # 8.8 List active BPF maps
  RAW_OUT="${SECTION_DIR}/08_bpftool_map.txt"
  run_check "List active BPF maps" "T1215" "bpftool map list 2>/dev/null" "$RAW_OUT"

  # 8.9 Audit kernel syscall hooks via BPF (tracee-ebpf)
  RAW_OUT="${SECTION_DIR}/09_tracee_list.txt"
  run_check "Audit kernel syscall hooks via BPF (tracee-ebpf)" "T1215" "tracee-ebpf --list" "$RAW_OUT"

  html_footer
}

# 9. Container & VM Indicators
scan_container_vm() {
  SECTION_NAME="Container & VM Indicators"
  DIR_NAME="$(section_dir container)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 9.1 List running Docker containers
  RAW_OUT="${SECTION_DIR}/01_docker_ps.txt"
  run_check "List running Docker containers" "T1536" "docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}'" "$RAW_OUT"

  # 9.2 Check Docker container mounts (requires jq)
  RAW_OUT="${SECTION_DIR}/02_docker_mounts.txt"
  run_check "Check Docker container mounts" "T1536" "jq '.Mounts' /var/lib/docker/containers/*/config.v2.json 2>/dev/null" "$RAW_OUT"

  # 9.3 Inspect KVM/QEMU VM logs
  RAW_OUT="${SECTION_DIR}/03_libvirt_logs.txt"
  run_check "Inspect KVM/QEMU VM logs" "T1562.003" "ls /var/log/libvirt/qemu 2>/dev/null" "$RAW_OUT"

  html_footer
}

# 10. Persistence & Backdoor Evidence
scan_persistence() {
  SECTION_NAME="Persistence & Backdoor Evidence"
  DIR_NAME="$(section_dir persistence)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 10.1 Inspect /etc/rc.local
  RAW_OUT="${SECTION_DIR}/01_rc_local.txt"
  run_check "Inspect /etc/rc.local" "T1547" "cat /etc/rc.local 2>/dev/null" "$RAW_OUT"

  # 10.2 List scripts in init directories
  RAW_OUT="${SECTION_DIR}/02_init_scripts.txt"
  run_check "List scripts in init directories" "T1547" "ls /etc/init.d/ /etc/rc*.d/ 2>/dev/null" "$RAW_OUT"

  # 10.3 List systemd unit files and statuses
  RAW_OUT="${SECTION_DIR}/03_systemd_units.txt"
  run_check "List systemd unit files and statuses" "T1547" "systemctl list-unit-files --type=service --state=enabled" "$RAW_OUT"

  # 10.4 Check SSH persistence in root’s home
  RAW_OUT="${SECTION_DIR}/04_root_ssh_keys.txt"
  run_check "Check SSH persistence in root’s home" "T1574.002" "ls /root/.ssh/authorized_keys 2>/dev/null" "$RAW_OUT"

  # 10.5 Check for hidden cron entries
  RAW_OUT="${SECTION_DIR}/05_hidden_cron.txt"
  run_check "Check for hidden cron entries" "T1053" "grep -R '.' /var/spool/cron/crontabs 2>/dev/null" "$RAW_OUT"

  html_footer
}

# 11. Indicator & Timeline Correlation
scan_timeline() {
  SECTION_NAME="Indicator & Timeline Correlation"
  DIR_NAME="$(section_dir timeline)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # 11.1 Uptime & unexpected reboots
  RAW_OUT="${SECTION_DIR}/01_uptime.txt"
  run_check "Uptime & unexpected reboots" "T1050" "uptime" "$RAW_OUT"

  # 11.2 Correlate user logins with suspicious times
  RAW_OUT="${SECTION_DIR}/02_last_logins.txt"
  run_check "Correlate user logins with suspicious times" "T1087" "last -s -7days" "$RAW_OUT"

  # 11.3 Check for gaps in logs
  RAW_OUT="${SECTION_DIR}/03_journal_verify.txt"
  run_check "Check for gaps in logs" "T1005" "journalctl --verify 2>/dev/null" "$RAW_OUT"

  html_footer
}

###############################################################################
###  Master HTML Index Generation
###############################################################################
generate_master_index() {
  INDEX_FILE="${ROOT_DIR}/index.html"
  SYSTEM_INFO="$(sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "${ROOT_DIR}/system_info.txt")"

  cat <<EOF > "$INDEX_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Forensics Scan Report - ${TIMESTAMP}</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    pre { background-color: #f4f4f4; padding: 10px; }
    a { text-decoration: none; color: #0366d6; }
    ul { list-style-type: none; padding: 0; }
    li { margin: 5px 0; }
    .skipped { color: #888; }
  </style>
</head>
<body>
  <h1>Forensics Scan Report</h1>
  <p><strong>Generated:</strong> $(date -u)</p>
  <h2>System Information</h2>
  <pre>
${SYSTEM_INFO}
  </pre>
  <h2>Sections</h2>
  <ul>
EOF

  # Iterate over all sections, link if run, else mark skipped
  for SEC in $ALL_SECTIONS; do
    DIR_NAME="$(section_dir $SEC)"
    TITLE="$(display_title $SEC)"
    if echo "$SECTIONS" | grep -wq "$SEC"; then
      echo "    <li><a href=\"${DIR_NAME}/index.html\">${TITLE} [RUN]</a></li>" >> "$INDEX_FILE"
    else
      echo "    <li class=\"skipped\">${TITLE} [SKIPPED]</li>" >> "$INDEX_FILE"
    fi
  done

  cat <<EOF >> "$INDEX_FILE"
  </ul>
</body>
</html>
EOF
}

###############################################################################
###  Argument Parsing & Execution Flow
###############################################################################
usage() {
  echo "Usage: $0 [--all] [kernel] [proc] [fs] [network] [users] [logs] [live] [dfir] [container] [persistence] [timeline]"
  echo "Specify multiple sections in any order, or --all for all sections."
  exit 1
}

if [ $# -lt 1 ]; then
  usage
fi

# Determine sections to run
SECTIONS=""
for ARG in "$@"; do
  if [ "$ARG" = "--all" ]; then
    SECTIONS="$ALL_SECTIONS"
    break
  fi
  # Validate argument
  if echo "$ALL_SECTIONS" | grep -wq "$ARG"; then
    SECTIONS="$SECTIONS $ARG"
  else
    echo "Unknown section: $ARG"
    usage
  fi
done

# Remove leading/trailing whitespace and duplicates
SECTIONS="$(echo $SECTIONS | tr ' ' '\n' | awk '!x[$0]++' | tr '\n' ' ')"

# If --all was present, we already set SECTIONS
if echo "$@" | grep -wq -- "--all"; then
  SECTIONS="$ALL_SECTIONS"
fi

# Create base directories and system info
print_system_info

# Run requested sections
for SECTION in $SECTIONS; do
  case "$SECTION" in
    kernel)      scan_kernel_modules ;;
    proc)        scan_proc_artifacts ;;
    fs)          scan_filesystem_integrity ;;
    network)     scan_network_indicators ;;
    users)       scan_user_accounts ;;
    logs)        scan_system_logs ;;
    live)        scan_live_forensics ;;
    dfir)        scan_dfir_tools ;;
    container)   scan_container_vm ;;
    persistence) scan_persistence ;;
    timeline)    scan_timeline ;;
  esac
done

# Generate master HTML index
generate_master_index

echo "Scan complete. Output directory: ${ROOT_DIR}"