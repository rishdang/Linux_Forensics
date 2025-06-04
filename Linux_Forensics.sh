#!/bin/sh
#
# linux_forensics_scan.sh v0.1 (section‐level parallel, live features disabled by default)
#
# A modular shell script to perform native Linux/Unix compromise-detection checks,
# organize raw outputs and HTML reports by section, and generate a master HTML index.
# - Each section runs in its own background job when multiple sections are specified.
# - Live memory (AVML/LiME) and disk imaging (dd) are disabled by default; edit the script to enable them.
# Created by Rishabh Dangwal
#
# Usage:
#   ./linux_forensics_scan.sh --all
#   ./linux_forensics_scan.sh [kernel fs proc network users logs live dfir container persistence timeline]
#
# Disabled-by-default features:
#   * Live RAM dumps (AVML/LiME) and DD-based disk imaging are disabled unless explicitly enabled by uncommenting the relevant lines.

VERSION="0.1 (section‐level parallel)"

###############################################################################
###  HELP / USAGE
###############################################################################
usage() {
  cat <<EOF
Usage: $0 [--all] [kernel] [proc] [fs] [network] [users] [logs] [live] [dfir] [container] [persistence] [timeline]

Specify one or more sections (in any order). If "--all" is given, all sections run.
Note: Live memory dumps (AVML/LiME) and disk imaging (dd) are disabled by default.

Sections:
  kernel      Kernel & Modules
  proc        /proc & Process Artifacts
  fs          Filesystem Integrity & Attributes
  network     Network Indicators
  users       User Accounts & Authentication
  logs        System Logs & Audit Trails
  live        Live Memory & Disk Forensics
  dfir        CLI & DFIR Tools
  container   Container & VM Indicators
  persistence Persistence & Backdoor Evidence
  timeline    Indicator & Timeline Correlation

To enable live RAM dump or disk imaging, uncomment or modify the relevant commands in the "live_checks" variable.
EOF
  exit 1
}

if [ $# -lt 1 ]; then
  usage
fi

###############################################################################
###  Section Titles & Directory Names
###############################################################################
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

section_dir() {
  case "$1" in
    kernel)      echo "01_kernel_modules";;
    proc)        echo "02_proc_artifacts";;
    fs)          echo "03_filesystem_checks";;
    network)     echo "04_network_checks";;
    users)       echo "05_user_account_checks";;
    logs)        echo "06_log_audit_checks";;
    live)        echo "07_live_memory_disk";;
    dfir)        echo "08_dfir_tools";;
    container)   echo "09_container_vm_checks";;
    persistence) echo "10_persistence_checks";;
    timeline)    echo "11_timeline_artifacts";;
    *)           echo "";;  # Should never happen if validated earlier
  esac
}

################################################################################
###  UTILITY CHECK & HTML HEADER/FOOTER HELPERS
################################################################################
require_util() {
  UTIL_NAME="$1"
  if ! command -v "$UTIL_NAME" >/dev/null 2>&1; then
    SKIP_UTIL=1
    return 1
  fi
  SKIP_UTIL=0
  return 0
}

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
    a { text-decoration: none; color: #000; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>${SECTION_TITLE}</h1>
  <p><a href="../index.html">&larr; Back to report index</a></p>
EOF
}

html_footer() {
  cat <<EOF >> "$HTML_FILE"
</body>
</html>
EOF
}

run_check() {
  TECH_DESC="$1"
  TTP="$2"
  CMD="$3"
  RAW_OUT="$4"

  echo "<h2>Technique: ${TECH_DESC}</h2>" >> "$HTML_FILE"
  echo "<p><strong>MITRE ATT&CK TTP:</strong> ${TTP}</p>" >> "$HTML_FILE"
  echo "<p><code>${CMD}</code></p>" >> "$HTML_FILE"
  echo "<pre>" >> "$HTML_FILE"

  UTIL="$(printf "%s" "$CMD" | tr '\n' ' ' | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f1)"
  require_util "$UTIL"
  if [ "$SKIP_UTIL" -eq 1 ]; then
    echo "Utility ${UTIL} not found. Skipping this check." > "$RAW_OUT"
    echo "Utility ${UTIL} not found. Skipping this check." >> "$HTML_FILE"
    echo "Check performed [NO] : Utility not present"
  else
    sh -c "$CMD" > "$RAW_OUT" 2>&1
    RC=$?
    if [ $RC -ne 0 ]; then
      sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$RAW_OUT" >> "$HTML_FILE"
      echo "Check performed [NO] : Exit code ${RC}"
    else
      sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$RAW_OUT" >> "$HTML_FILE"
      echo "Check performed [OK]"
    fi
  fi

  echo "</pre>" >> "$HTML_FILE"
}

run_section() {
  SECTION="$1"
  CHECKS_VAR="$2"
  SECTION_NAME="$(display_title "$SECTION")"
  DIR_NAME="$(section_dir "$SECTION")"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  if ! mkdir -p "${SECTION_DIR}"; then
    echo "ERROR: Could not create directory '${SECTION_DIR}'." >&2
    return 1
  fi

  html_header "$SECTION_NAME"

  # Retrieve the pipe-separated list of TECH_DESC|TTP|CMD
  LIST=$(eval "printf '%s\n' \"\${${CHECKS_VAR}}\"")
  TOTAL_CHECKS=$(echo "$LIST" | grep -c '^[^ ]')
  COUNTER=0

  while IFS='|' read -r TECH_DESC TTP CMD; do
    COUNTER=$((COUNTER + 1))
    echo "    [${SECTION_NAME}] Running check ${COUNTER}/${TOTAL_CHECKS}: ${TECH_DESC}"
    SAFE_DESC="$(printf "%s" "$TECH_DESC" | tr ' /' '_' )"
    RAW_OUT="${SECTION_DIR}/$(printf '%02d' "$COUNTER")_${SAFE_DESC}.txt"
    run_check "$TECH_DESC" "$TTP" "$CMD" "$RAW_OUT"
  done <<EOF
$LIST
EOF

  html_footer
  echo "    [${SECTION_NAME}] Completed (${TOTAL_CHECKS}/${TOTAL_CHECKS} checks)."
}

generate_master_index() {
  INDEX_FILE="${ROOT_DIR}/index.html"

  # Read, escape, and embed system info
  SYSTEM_INFO="$(sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "${ROOT_DIR}/system_info.txt")"

  cat <<EOF > "$INDEX_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Forensics Scan Report - ${TIMESTAMP}</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    ul { list-style-type: none; padding: 0; }
    li { margin: 5px 0; }
    .skipped { color: #888; }
    a { text-decoration: none; color: #000; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>Forensics Scan Report</h1>
  <p><strong>Version:</strong> ${VERSION}</p>
  <p><strong>Generated:</strong> ${TIMESTAMP}</p>
  <h2>System Information</h2>
  <pre>${SYSTEM_INFO}</pre>
  <h2>Sections</h2>
  <ul>
EOF

  for SEC in $ALL_SECTIONS; do
    # Only link those sections that were actually requested
    case " $SECTIONS " in
      *" $SEC "*) 
        DIR_NAME="$(section_dir "$SEC")"
        TITLE="$(display_title "$SEC")"
        if [ -d "${ROOT_DIR}/${DIR_NAME}" ] && [ -f "${ROOT_DIR}/${DIR_NAME}/index.html" ]; then
          echo "    <li><a href=\"${DIR_NAME}/index.html\">${TITLE} [RUN]</a></li>" >> "$INDEX_FILE"
        else
          echo "    <li class=\"skipped\">${TITLE} [ERROR]</li>" >> "$INDEX_FILE"
        fi
        ;;
      *)
        TITLE="$(display_title "$SEC")"
        echo "    <li class=\"skipped\">${TITLE} [SKIPPED]</li>" >> "$INDEX_FILE"
        ;;
    esac
  done

  cat <<EOF >> "$INDEX_FILE"
  </ul>
</body>
</html>
EOF
}

print_system_info() {
  INFO_FILE="${ROOT_DIR}/system_info.txt"
  if ! mkdir -p "$ROOT_DIR"; then
    echo "ERROR: Could not create output directory '${ROOT_DIR}'." >&2
    exit 1
  fi

  {
    echo "Hostname: $(hostname)"
    echo "Date: $(date -u)"
    echo "OS Details: $(uname -a || echo "uname not available")"
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

################################################################################
###  DEFINE ALL CHECK-LISTS (TECH_DESC|TTP|CMD)
################################################################################

ALL_SECTIONS="kernel proc fs network users logs live dfir container persistence timeline"

kernel_checks="
List loaded kernel modules|T1215|lsmod
Check for kernel taint|T1215|cat /proc/sys/kernel/tainted
Compare lsmod vs /sys/module|T1215|lsmod | tail -n +2 | awk '{print \$1}' > \${ROOT_DIR}/__tmp1.lst && ls /sys/module | sort > \${ROOT_DIR}/__tmp2.lst && diff \${ROOT_DIR}/__tmp1.lst \${ROOT_DIR}/__tmp2.lst && rm -f \${ROOT_DIR}/__tmp1.lst \${ROOT_DIR}/__tmp2.lst
Detect hidden/malicious modules|T1215|lsmod | tail -n +2 | awk '{print \$1}' > \${ROOT_DIR}/__tmp1.lst && ls /sys/module | sort > \${ROOT_DIR}/__tmp2.lst && comm -23 \${ROOT_DIR}/__tmp1.lst \${ROOT_DIR}/__tmp2.lst && rm -f \${ROOT_DIR}/__tmp1.lst \${ROOT_DIR}/__tmp2.lst
Check for eBPF/tracing hooks|T1215|cat /sys/kernel/debug/tracing/available_filter_functions 2>/dev/null || echo \"No eBPF filters available\"; cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null
"

proc_checks="
Processes running deleted binaries|T1055|ls -alR /proc/*/exe 2>/dev/null | grep deleted
List open files|T1055|lsof -nP 2>/dev/null
Active TCP connections|T1049|cat /proc/net/tcp
"

fs_checks="
SUID/SGID files|T1059|find / -perm /4000 2>/dev/null
Recently modified files (last 24h)|T1007|find / -mtime -1 2>/dev/null
Disk usage|T1083|df -h
"

network_checks="
Open listening sockets|T1040|netstat -tunlp 2>/dev/null
Firewall rules|T1564|iptables -L -nv 2>/dev/null
Socket stats|T1049|ss -tulpn 2>/dev/null
"

users_checks="
List /etc/passwd|T1087.001|cat /etc/passwd
List /etc/shadow|T1087.002|cat /etc/shadow
List sudoers group members|T1059.003|getent group sudo
"

logs_checks="
Failed SSH logins|T1110|grep -i 'failed password' /var/log/auth.log 2>/dev/null
System journal errors|T1005|journalctl -p err --no-pager 2>/dev/null
Recent dmesg entries|T1005|dmesg | tail -n 50
"

# (Disabled by default: uncomment to enable live dumps)
live_checks="
# Live memory dump with AVML (requires root and AVML installed)
# T1055|avml --output \"\${ROOT_DIR}/memory.avml\"
# Live disk image (requires root)
# T1564|dd if=/dev/sda of=\"\${ROOT_DIR}/disk.img\" bs=1M
Echo placeholder: Live memory/disk forensics are disabled by default. Edit the script to enable them.
"

dfir_checks="
chkrootkit|T1016|chkrootkit
rkhunter|T1007|rkhunter --check
# volatility|T1560|volatility -f \"/dev/sda\" imageinfo
"

container_checks="
Docker cgroup artifacts|T1610|grep -qa docker /proc/1/cgroup && echo 'Docker cgroup found'
Detect VM/container|T1611|systemd-detect-virt --quiet && echo \"Inside VM or container\"
"

persistence_checks="
Cron jobs|T1053|ls -la /etc/cron.d 2>/dev/null
Bashrc injections|T1543|grep -R 'bash -i' /home 2>/dev/null
Enabled systemd units|T1547|systemctl list-unit-files | grep enabled
"

timeline_checks="
Log file timestamps|T1082|find /var/log -type f -printf '%TY-%Tm-%Td %TT %p\n' 2>/dev/null | sort
User login history|T1056|last -F
"

################################################################################
###  MAIN ARGUMENT PARSING & PREPARE SECTIONS
################################################################################
# (We replace the original grep-based validation with 'case ... in' for exact matches.)

SECTIONS=""

for ARG in "$@"; do
  case "$ARG" in
    --all)
      SECTIONS="$ALL_SECTIONS"
      break
      ;;
    kernel|proc|fs|network|users|logs|live|dfir|container|persistence|timeline)
      SECTIONS="$SECTIONS $ARG"
      ;;
    *)
      echo "Unknown section: '$ARG'"
      usage
      ;;
  esac
done

# Trim any leading/trailing spaces
SECTIONS="$(echo "$SECTIONS" | xargs)"

if [ -z "$SECTIONS" ]; then
  usage
fi

# Use UTC timestamp in ISO format (YYYYMMDD_HHMMSSZ)
TIMESTAMP="$(date -u +'%Y%m%d_%H%M%SZ')"
ROOT_DIR="forensics_output_${TIMESTAMP}"

# Create the top-level output directory (error if it fails)
if ! mkdir -p "$ROOT_DIR"; then
  echo "ERROR: Could not create output directory '$ROOT_DIR'." >&2
  exit 1
fi

echo "linux_forensics_scan.sh version ${VERSION}"
if [ "$(id -u)" -ne 0 ]; then
  echo "Warning: not running as root; root-only checks will be skipped."
fi

print_system_info

TOTAL_SECTIONS=$(echo "$SECTIONS" | wc -w)
CUR_SECTION=0
PIDS=""

################################################################################
###  LAUNCH EACH REQUESTED SECTION IN PARALLEL (WITH A PROGRESS BANNER)
################################################################################
for SECTION in $SECTIONS; do
  CUR_SECTION=$((CUR_SECTION + 1))
  SECTION_NAME="$(display_title "$SECTION")"
  echo "Overall progress: Section ${CUR_SECTION}/${TOTAL_SECTIONS} - '${SECTION_NAME}'"

  case "$SECTION" in
    kernel)      run_section "$SECTION" "kernel_checks" ;;
    proc)        run_section "$SECTION" "proc_checks" ;;
    fs)          run_section "$SECTION" "fs_checks" ;;
    network)     run_section "$SECTION" "network_checks" ;;
    users)       run_section "$SECTION" "users_checks" ;;
    logs)        run_section "$SECTION" "logs_checks" ;;
    live)        run_section "$SECTION" "live_checks" ;;
    dfir)        run_section "$SECTION" "dfir_checks" ;;
    container)   run_section "$SECTION" "container_checks" ;;
    persistence) run_section "$SECTION" "persistence_checks" ;;
    timeline)    run_section "$SECTION" "timeline_checks" ;;
  esac &
  PIDS="$PIDS $!"
done

# Wait for all background jobs to finish
for pid in $PIDS; do
  wait "$pid" || echo "WARNING: One background job (PID $pid) exited with an error."
done

generate_master_index

echo "Scan complete. Output directory: ${ROOT_DIR}"
exit 0