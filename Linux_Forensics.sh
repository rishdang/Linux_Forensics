#!/bin/bash
#
# linux_forensics_scan.sh v0.1 (extended: JSON, TAR, ZIP, CSV, REPORT; improved counting, root‐index table, section findings)
#
# - Retains all original pipelines and comments as “checks” (so total matches original count).
# - Any line beginning with “#” is treated as a SKIPPED check.
# - Root index shows a table (Section | Link | Total | OK | SKIPPED | FAILED).
# - Child indexes have navigation tables and links.
# - New flag: --report → generates an executive HTML summary, including per‐section findings.
# - CSV/JSON/TAR/ZIP exports otherwise unchanged.
#
# Created by Rishabh Dangwal

VERSION="0.1 (extended: JSON, TAR, ZIP, CSV, REPORT; improved counting, root‐index table, section findings)"

###############################################################################
###  HELP / USAGE
###############################################################################
usage() {
  cat <<EOF
Usage: $0 [--all | <section> ...] [--json] [--csv] [--tar] [--zip] [--report]

Flags (must appear before any section names):
  --all      Run all sections in predefined order
  --json     Export summary as JSON
  --csv      Export summary as CSV
  --tar      Create a .tar.gz archive of the output directory
  --zip      Create a .zip archive of the output directory
  --report   Create an executive HTML summary of the scan

Valid sections (choose one or more, unless --all):
  kernel      Kernel & Modules
  proc        /proc & Process Artifacts
  fs          Filesystem Integrity & Attributes
  network     Network Indicators
  users       User Accounts & Authentication
  logs        System Logs & Audit Trails
  live        Live Memory & Disk Forensics (disabled by default)
  dfir        CLI & DFIR Tools
  container   Container & VM Indicators
  persistence Persistence & Backdoor Evidence
  timeline    Indicator & Timeline Correlation

Examples:
  \$0 --all --report
  \$0 kernel fs users --csv --report
  \$0 proc logs --json --zip --report

Lines beginning with “#” in any list are treated as SKIPPED checks.
EOF
  exit 1
}

###############################################################################
###  PARSE GLOBAL FLAGS & SECTIONS
###############################################################################
EXPORT_JSON=0
EXPORT_CSV=0
EXPORT_TAR=0
EXPORT_ZIP=0
EXPORT_REPORT=0

declare -a ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --json) EXPORT_JSON=1; shift ;;
    --csv)  EXPORT_CSV=1;  shift ;;
    --tar)  EXPORT_TAR=1;  shift ;;
    --zip)  EXPORT_ZIP=1;  shift ;;
    --report) EXPORT_REPORT=1; shift ;;
    --all|kernel|proc|fs|network|users|logs|live|dfir|container|persistence|timeline)
      ARGS+=("$1"); shift ;;
    *)
      echo "Unknown flag or section: '$1'"
      usage
      ;;
  esac
done

if [ ${#ARGS[@]} -eq 0 ]; then
  usage
fi

ALL_SECTIONS="kernel proc fs network users logs live dfir container persistence timeline"
SECTIONS=""

for ARG in "${ARGS[@]}"; do
  case "$ARG" in
    --all)
      SECTIONS="$ALL_SECTIONS"
      break
      ;;
    kernel|proc|fs|network|users|logs|live|dfir|container|persistence|timeline)
      if [[ " $SECTIONS " != *" $ARG "* ]]; then
        SECTIONS="$SECTIONS $ARG"
      fi
      ;;
  esac
done

SECTIONS="$(echo "$SECTIONS" | xargs)"
if [ -z "$SECTIONS" ]; then
  usage
fi

###############################################################################
###  SET UP OUTPUT DIRECTORY & TEMP FILES FOR SUMMARY
###############################################################################
TIMESTAMP="$(date -u +'%Y%m%d_%H%M%SZ')"
ROOT_DIR="forensics_output_${TIMESTAMP}"

if ! mkdir -p "$ROOT_DIR"; then
  echo "ERROR: Could not create output directory '$ROOT_DIR'." >&2
  exit 1
fi

JSON_TMP="${ROOT_DIR}/.json_lines.tmp"
CSV_TMP="${ROOT_DIR}/.csv_lines.tmp"
: > "$JSON_TMP"
: > "$CSV_TMP"

###############################################################################
###  PRINT BANNER & SYSTEM INFO
###############################################################################
echo "linux_forensics_scan.sh version ${VERSION}"
if [ "$(id -u)" -ne 0 ]; then
  echo "Warning: not running as root; root-only checks will be skipped."
fi

print_system_info() {
  INFO_FILE="${ROOT_DIR}/system_info.txt"
  {
    echo "Hostname: $(hostname 2>/dev/null || echo 'N/A')"
    echo "Date (UTC): $(date -u)"
    echo "OS Details: $(uname -a 2>/dev/null || echo 'N/A')"
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

print_system_info

###############################################################################
###  UTILITY CHECK & HTML HELPERS
###############################################################################
require_util() {
  local UTIL_NAME="$1"
  if ! command -v "$UTIL_NAME" >/dev/null 2>&1; then
    SKIP_UTIL=1
    return 1
  fi
  SKIP_UTIL=0
  return 0
}

html_header() {
  local SECTION_TITLE="$1"
  cat <<EOF > "$HTML_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${SECTION_TITLE}</title>
  <style>
    body { font-family: "Times New Roman", serif; margin: 20px; }
    pre { background-color: #f4f4f4; padding: 10px; overflow-x: auto; }
    code { font-family: monospace; }
    h1 { margin-bottom: 0.5em; }
    h2 { border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 1.5em; }
    table { border-collapse: collapse; margin-bottom: 1em; width: 100%; }
    table, th, td { border: 1px solid #888; padding: 5px; text-align: left; }
    a { text-decoration: none; color: #0066cc; }
    a:hover { text-decoration: underline; }
    .summary-table { margin-top: 1em; margin-bottom: 1em; }
    .section-table th { background-color: #eee; }
  </style>
</head>
<body>
  <a id="top"></a>
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

###############################################################################
###  CORE FUNCTION: run_check
###############################################################################
run_check() {
  local SECTION="$1"
  local TECH_DESC="$2"
  local TTP="$3"
  local CMD_RAW="$4"
  local RAW_OUT="$5"

  # Replace placeholder with actual ROOT_DIR at runtime
  local CMD="${CMD_RAW//__ROOTDIR__/$ROOT_DIR}"

  # Build JSON base (append status later)
  local JSON_BASE
  JSON_BASE="{\"section\":\"${SECTION}\",\"technique\":\"$(printf '%s' "${TECH_DESC}" | sed 's/"/\\"/g')\",\"ttp\":\"${TTP}\",\"command\":\"$(printf '%s' "${CMD}" | sed 's/"/\\"/g')\",\"status\":"

  # Screen output includes TTP
  echo "    [${SECTION}] Running check ${CHECK_IDX}/${TOTAL_CHECKS}: ${TECH_DESC} (TTP: ${TTP})"

  echo "<h2 id=\"tech${CHECK_IDX}\">Technique: ${TECH_DESC}</h2>" >> "$HTML_FILE"
  echo "<p><strong>MITRE ATT&CK TTP:</strong> ${TTP}</p>" >> "$HTML_FILE"
  echo "<p><code>${CMD}</code></p>" >> "$HTML_FILE"
  echo "<pre>" >> "$HTML_FILE"

  # If line starts with optional whitespace + "#", treat as SKIPPED
  if [[ "$CMD_RAW" =~ ^[[:space:]]*# ]]; then
    STATUS="SKIPPED"
    echo "SKIPPED (commented out)" > "$RAW_OUT"
    echo "SKIPPED (commented out)" >> "$HTML_FILE"
    echo "</pre>" >> "$HTML_FILE"
    echo "<p>[<a href=\"#top\">Back to Top</a> | <a href=\"../index.html\">Back to Index</a>]</p>" >> "$HTML_FILE"
  else
    local UTIL
    UTIL="$(printf '%s' "$CMD" | tr '\n' ' ' | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f1)"

    require_util "$UTIL"
    if [ "$SKIP_UTIL" -eq 1 ]; then
      STATUS="SKIPPED"
      echo "Utility ${UTIL} not found. Skipping this check." > "$RAW_OUT"
      echo "Utility ${UTIL} not found. Skipping this check." >> "$HTML_FILE"
      echo "</pre>" >> "$HTML_FILE"
      echo "<p>[<a href=\"#top\">Back to Top</a> | <a href=\"../index.html\">Back to Index</a>]</p>" >> "$HTML_FILE"
    else
      bash -c "$CMD" > "$RAW_OUT" 2>&1
      local RC=$?
      if [ $RC -ne 0 ]; then
        STATUS="FAILED"
        sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/' "$RAW_OUT" >> "$HTML_FILE"
        echo "</pre>" >> "$HTML_FILE"
        echo "<p><em>Exit code: ${RC}</em></p>" >> "$HTML_FILE"
        echo "<p>[<a href=\"#top\">Back to Top</a> | <a href=\"../index.html\">Back to Index</a>]</p>" >> "$HTML_FILE"
      else
        STATUS="OK"
        sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/' "$RAW_OUT" >> "$HTML_FILE"
        echo "</pre>" >> "$HTML_FILE"
        echo "<p>[<a href=\"#top\">Back to Top</a> | <a href=\"../index.html\">Back to Index</a>]</p>" >> "$HTML_FILE"
      fi
    fi
  fi

  # Append a CSV row
  printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n" \
    "$SECTION" \
    "$(printf '%s' "$TECH_DESC" | sed 's/"/""/g')" \
    "$TTP" \
    "$(printf '%s' "$CMD" | sed 's/"/""/g')" \
    "$STATUS" \
    >> "$CSV_TMP"

  # Append a JSON object (with trailing comma)
  printf "%s\"%s\"},\n" "$JSON_BASE" "$STATUS" >> "$JSON_TMP"
}

###############################################################################
###  DEFINE ALL CHECK-LISTS (PIPE-SEPARATED: TECH_DESC|TTP|CMD_RAW)
###  Use single‐quoted heredocs so that pipes, redirections and comments remain literal.
###  Use __ROOTDIR__ placeholder for paths under $ROOT_DIR.
###############################################################################
read -r -d '' kernel_checks <<'EOF'
List loaded kernel modules|T1215|lsmod
Check for kernel taint|T1215|cat /proc/sys/kernel/tainted
Compare lsmod vs /sys/module|T1215|lsmod | tail -n +2 | awk '{print $1}' > __ROOTDIR__/__tmp1.lst && ls /sys/module | sort > __ROOTDIR__/__tmp2.lst && diff __ROOTDIR__/__tmp1.lst __ROOTDIR__/__tmp2.lst && rm -f __ROOTDIR__/__tmp1.lst __ROOTDIR__/__tmp2.lst
Detect hidden/malicious modules|T1215|lsmod | tail -n +2 | awk '{print $1}' > __ROOTDIR__/__tmp1.lst && ls /sys/module | sort > __ROOTDIR__/__tmp2.lst && comm -23 __ROOTDIR__/__tmp1.lst __ROOTDIR__/__tmp2.lst && rm -f __ROOTDIR__/__tmp1.lst __ROOTDIR__/__tmp2.lst
Check for eBPF/tracing hooks|T1215|cat /sys/kernel/debug/tracing/available_filter_functions 2>/dev/null || echo "No eBPF filters available"; cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null
EOF

read -r -d '' proc_checks <<'EOF'
Processes running deleted binaries|T1055|ls -alR /proc/*/exe 2>/dev/null | grep deleted
List open files|T1055|lsof -nP 2>/dev/null
Active TCP connections|T1049|cat /proc/net/tcp
EOF

read -r -d '' fs_checks <<'EOF'
SUID/SGID files|T1059|find / -perm /4000 2>/dev/null
Recently modified files (last 24h)|T1007|find / -mtime -1 2>/dev/null
Disk usage|T1083|df -h
EOF

read -r -d '' network_checks <<'EOF'
Open listening sockets|T1040|netstat -tunlp 2>/dev/null
Firewall rules|T1564|iptables -L -nv 2>/dev/null
Socket stats|T1049|ss -tulpn 2>/dev/null
EOF

read -r -d '' users_checks <<'EOF'
List /etc/passwd|T1087.001|cat /etc/passwd
List /etc/shadow|T1087.002|cat /etc/shadow
List sudoers group members|T1059.003|getent group sudo
EOF

read -r -d '' logs_checks <<'EOF'
Failed SSH logins|T1110|grep -i 'failed password' /var/log/auth.log 2>/dev/null
System journal errors|T1005|journalctl -p err --no-pager 2>/dev/null
Recent dmesg entries|T1005|dmesg | tail -n 50
EOF

read -r -d '' live_checks <<'EOF'
# Live memory dump with AVML (requires root & AVML installed)
# T1055|avml --output "__ROOTDIR__/memory.avml"
# Live disk image (requires root)
# T1564|dd if=/dev/sda of="__ROOTDIR__/disk.img" bs=1M
Echo placeholder: Live memory/disk forensics are disabled by default. Edit the script to enable them.
EOF

read -r -d '' dfir_checks <<'EOF'
chkrootkit|T1016|chkrootkit
rkhunter|T1007|rkhunter --check
# volatility|T1560|volatility -f "/dev/sda" imageinfo
EOF

read -r -d '' container_checks <<'EOF'
Docker cgroup artifacts|T1610|grep -qa docker /proc/1/cgroup && echo 'Docker cgroup found'
Detect VM/container|T1611|systemd-detect-virt --quiet && echo "Inside VM or container"
EOF

read -r -d '' persistence_checks <<'EOF'
Cron jobs|T1053|ls -la /etc/cron.d 2>/dev/null
Bashrc injections|T1543|grep -R 'bash -i' /home 2>/dev/null
Enabled systemd units|T1547|systemctl list-unit-files | grep enabled
EOF

read -r -d '' timeline_checks <<'EOF'
Log file timestamps|T1082|find /var/log -type f -printf '%TY-%Tm-%Td %TT %p\n' 2>/dev/null | sort
User login history|T1056|last -F
EOF

###############################################################################
###  SECTION-FOLDER & DISPLAY NAME HELPERS
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
    *)           echo "";;
  esac
}

###############################################################################
###  RUN A SINGLE SECTION (WRITES HTML + RAW OUT FILES)
###############################################################################
run_section() {
  local SECTION="$1"
  local CHECKS_VAR="$2"
  local SECTION_TITLE SECTION_DIR HTML_FILE LIST TOTAL_CHECKS idx SAFE_DESC RAW_FILE_NAME RAW_OUT

  SECTION_TITLE="$(display_title "$SECTION")"
  DIR_NAME="$(section_dir "$SECTION")"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  if ! mkdir -p "${SECTION_DIR}"; then
    echo "ERROR: Could not create directory '${SECTION_DIR}'." >&2
    return 1
  fi

  LIST=$(eval "printf '%s\n' \"\${${CHECKS_VAR}}\"")
  TOTAL_CHECKS=$(echo "$LIST" | wc -l)  # include commented lines
  if [ "$TOTAL_CHECKS" -eq 0 ]; then
    echo "No checks defined for section ${SECTION}."
    return 0
  fi

  html_header "$SECTION_TITLE"

  # Child index: navigation table (Technique | Raw Output)
  echo "<h2>Techniques &amp; Raw Output Files</h2>" >> "$HTML_FILE"
  echo "<table class=\"summary-table\">" >> "$HTML_FILE"
  echo "  <tr><th>#</th><th>Technique</th><th>Raw Output</th></tr>" >> "$HTML_FILE"

  idx=0
  while IFS='|' read -r TECH_DESC TTP CMD_RAW; do
    idx=$((idx + 1))
    SAFE_DESC="$(printf '%s' "$TECH_DESC" | sed 's/[^a-zA-Z0-9]/_/g')"
    RAW_FILE_NAME="$(printf '%02d' "$idx")_${SAFE_DESC}.txt"
    echo "  <tr><td>${idx}</td><td><a href=\"#tech${idx}\">${TECH_DESC}</a></td><td><a href=\"${RAW_FILE_NAME}\">${RAW_FILE_NAME}</a></td></tr>" >> "$HTML_FILE"
  done <<EOF
$LIST
EOF

  echo "</table>" >> "$HTML_FILE"
  echo "<p><a href=\"../index.html\">Back to Root Index</a></p>" >> "$HTML_FILE"

  # Now run each check
  idx=0
  while IFS='|' read -r TECH_DESC TTP CMD_RAW; do
    idx=$((idx + 1))
    SAFE_DESC="$(printf '%s' "$TECH_DESC" | sed 's/[^a-zA-Z0-9]/_/g')"
    RAW_OUT="${SECTION_DIR}/$(printf '%02d' "$idx")_${SAFE_DESC}.txt"

    CHECK_IDX="$idx"
    run_check "$SECTION" "$TECH_DESC" "$TTP" "$CMD_RAW" "$RAW_OUT"
  done <<EOF
$LIST
EOF

  html_footer
  echo "    [${SECTION_TITLE}] Completed (${TOTAL_CHECKS}/${TOTAL_CHECKS} checks)."
}

###############################################################################
###  MASTER INDEX GENERATION (WITH SECTION TABLE)
###############################################################################
generate_master_index() {
  local INDEX_FILE SYSTEM_INFO_RAW SYSTEM_INFO TOTAL_OVERALL SKIPPED_OVERALL FAILED_OVERALL SUCCESS_OVERALL
  INDEX_FILE="${ROOT_DIR}/index.html"

  # Overall summary (across all sections)
  if [ -s "$CSV_TMP" ]; then
    TOTAL_OVERALL=$(wc -l < "$CSV_TMP")
    SKIPPED_OVERALL=$(grep -c '"SKIPPED"' "$CSV_TMP")
    FAILED_OVERALL=$(grep -c '"FAILED"' "$CSV_TMP")
    SUCCESS_OVERALL=$((TOTAL_OVERALL - SKIPPED_OVERALL - FAILED_OVERALL))
  else
    TOTAL_OVERALL=0; SKIPPED_OVERALL=0; FAILED_OVERALL=0; SUCCESS_OVERALL=0
  fi

  SYSTEM_INFO_RAW="$(cat "${ROOT_DIR}/system_info.txt" 2>/dev/null)"
  SYSTEM_INFO="$(printf '%s' "$SYSTEM_INFO_RAW" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"

  cat <<EOF > "$INDEX_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Forensics Scan Report - ${TIMESTAMP}</title>
  <style>
    body { font-family: "Times New Roman", serif; margin: 20px; }
    pre { background-color: #f4f4f4; padding: 10px; overflow-x: auto; }
    code { font-family: monospace; }
    h1 { margin-bottom: 0.5em; }
    h2 { border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 1.5em; }
    table { border-collapse: collapse; margin-bottom: 1em; width: 100%; }
    table, th, td { border: 1px solid #888; padding: 5px; text-align: left; }
    a { text-decoration: none; color: #0066cc; }
    a:hover { text-decoration: underline; }
    .summary-table { margin-top: 1em; margin-bottom: 1em; }
    .section-table th { background-color: #eee; }
  </style>
</head>
<body>
  <h1>Forensics Scan Report</h1>
  <p><strong>Version:</strong> ${VERSION}</p>
  <p><strong>Generated (UTC):</strong> ${TIMESTAMP}</p>

  <h2>System Information</h2>
  <pre>${SYSTEM_INFO}</pre>

  <h2>Overall Summary of Checks</h2>
  <table class="summary-table">
    <tr><th>Total Checks</th><td>${TOTAL_OVERALL}</td></tr>
    <tr><th>Successful</th><td>${SUCCESS_OVERALL}</td></tr>
    <tr><th>Skipped</th><td>${SKIPPED_OVERALL}</td></tr>
    <tr><th>Failed</th><td>${FAILED_OVERALL}</td></tr>
  </table>

  <h2>Sections Detail</h2>
  <table class="section-table">
    <tr>
      <th>Section</th>
      <th>Link</th>
      <th>Total</th>
      <th>OK</th>
      <th>SKIPPED</th>
      <th>FAILED</th>
    </tr>
EOF

  for SEC in $ALL_SECTIONS; do
    local TITLE DIR_NAME SECTION_CSV TOTAL_SECTION SKIPPED_SECTION FAILED_SECTION OK_SECTION
    TITLE="$(display_title "$SEC")"
    DIR_NAME="$(section_dir "$SEC")"

    if [[ " $SECTIONS " == *" $SEC "* ]] && [ -d "${ROOT_DIR}/${DIR_NAME}" ] && [ -f "${ROOT_DIR}/${DIR_NAME}/index.html" ]; then
      SECTION_CSV=$(grep -E "^\"${SEC}\"" "$CSV_TMP")
      TOTAL_SECTION=$(echo "$SECTION_CSV" | wc -l)
      SKIPPED_SECTION=$(echo "$SECTION_CSV" | grep -c '"SKIPPED"')
      FAILED_SECTION=$(echo "$SECTION_CSV" | grep -c '"FAILED"')
      OK_SECTION=$((TOTAL_SECTION - SKIPPED_SECTION - FAILED_SECTION))

      echo "    <tr><td>${TITLE}</td><td><a href=\"${DIR_NAME}/index.html\">View</a></td><td>${TOTAL_SECTION}</td><td>${OK_SECTION}</td><td>${SKIPPED_SECTION}</td><td>${FAILED_SECTION}</td></tr>" >> "$INDEX_FILE"
    else
      echo "    <tr><td>${TITLE}</td><td><span style=\"color:#888;\">N/A</span></td><td>0</td><td>0</td><td>0</td><td>0</td></tr>" >> "$INDEX_FILE"
    fi
  done

  cat <<EOF >> "$INDEX_FILE"
  </table>
</body>
</html>
EOF
}

###############################################################################
###  EXECUTIVE REPORT GENERATION (WHEN --report IS SET)
###############################################################################
generate_executive_report() {
  local REPORT_FILE="${ROOT_DIR}/executive_summary.html"
  local SUMMARY_TOTAL SUMMARY_OK SUMMARY_SKIPPED SUMMARY_FAILED
  local FAILED_LIST SKIPPED_LIST

  # Overall summary
  SUMMARY_TOTAL=$(wc -l < "$CSV_TMP")
  SUMMARY_SKIPPED=$(grep -c '"SKIPPED"' "$CSV_TMP")
  SUMMARY_FAILED=$(grep -c '"FAILED"' "$CSV_TMP")
  SUMMARY_OK=$((SUMMARY_TOTAL - SUMMARY_SKIPPED - SUMMARY_FAILED))

  # Basic lists
  FAILED_LIST=$(grep '"FAILED"' "$CSV_TMP" | awk -F',' '{ gsub(/"/,"",$2); print $1": "$2 }')
  SKIPPED_LIST=$(grep '"SKIPPED"' "$CSV_TMP" | awk -F',' '{ gsub(/"/,"",$2); print $1": "$2 }')

  cat <<EOF > "$REPORT_FILE"
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Executive Summary - ${TIMESTAMP}</title>
  <style>
    body { font-family: "Times New Roman", serif; margin: 20px; }
    h1, h2, h3 { margin-top: 1em; }
    table { border-collapse: collapse; margin-bottom: 1em; width: 100%; }
    table, th, td { border: 1px solid #888; padding: 5px; text-align: left; }
    th { background-color: #eee; }
    ul { margin: 0; padding-left: 1.2em; }
    li { margin: 0.2em 0; }
    code { background-color: #f4f4f4; padding: 2px 4px; }
    a { text-decoration: none; color: #0066cc; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>Executive Summary</h1>
  <p><strong>Scan Timestamp (UTC):</strong> ${TIMESTAMP}</p>

  <h2>Executive Overview</h2>
  <p>This report provides a high-level summary of the forensic scan performed on the host. It covers each section’s total checks, successes, skips, failures, and notable findings.</p>

  <h2>Overall Statistics</h2>
  <table>
    <tr><th>Total Checks Performed</th><td>${SUMMARY_TOTAL}</td></tr>
    <tr><th>Successful Checks</th><td>${SUMMARY_OK}</td></tr>
    <tr><th>Skipped Checks</th><td>${SUMMARY_SKIPPED}</td></tr>
    <tr><th>Failed Checks</th><td>${SUMMARY_FAILED}</td></tr>
  </table>

  <h2>Sections Summary</h2>
  <table>
    <tr>
      <th>Section</th>
      <th>Total</th>
      <th>OK</th>
      <th>SKIPPED</th>
      <th>FAILED</th>
    </tr>
EOF

  for SEC in $ALL_SECTIONS; do
    local TITLE DIR_NAME SECTION_CSV TOTAL_SECTION SKIPPED_SECTION FAILED_SECTION OK_SECTION
    TITLE="$(display_title "$SEC")"
    DIR_NAME="$(section_dir "$SEC")"

    if [[ " $SECTIONS " == *" $SEC "* ]] && [ -d "${ROOT_DIR}/${DIR_NAME}" ] && [ -f "${ROOT_DIR}/${DIR_NAME}/index.html" ]; then
      SECTION_CSV=$(grep -E "^\"${SEC}\"" "$CSV_TMP")
      TOTAL_SECTION=$(echo "$SECTION_CSV" | wc -l)
      SKIPPED_SECTION=$(echo "$SECTION_CSV" | grep -c '"SKIPPED"')
      FAILED_SECTION=$(echo "$SECTION_CSV" | grep -c '"FAILED"')
      OK_SECTION=$((TOTAL_SECTION - SKIPPED_SECTION - FAILED_SECTION))
      echo "    <tr><td>${TITLE}</td><td>${TOTAL_SECTION}</td><td>${OK_SECTION}</td><td>${SKIPPED_SECTION}</td><td>${FAILED_SECTION}</td></tr>" >> "$REPORT_FILE"
    else
      echo "    <tr><td>${TITLE}</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>" >> "$REPORT_FILE"
    fi
  done

  cat <<EOF >> "$REPORT_FILE"
  </table>

  <h2>Section‐Specific Findings</h2>
EOF

  # Proc section findings:
  if [[ " $SECTIONS " == *" proc "* ]]; then
    local PROC_DIR="${ROOT_DIR}/02_proc_artifacts"
    local PR_FIND DB_COUNT OF_COUNT TCP_COUNT
    PR_FIND=$(grep -v '^$' "${PROC_DIR}/01_Processes_running_deleted_binaries.txt" | grep -v "SKIPPED" | wc -l)
    OF_COUNT=$(grep -v '^$' "${PROC_DIR}/02_List_open_files.txt" | grep -v "SKIPPED" | wc -l)
    TCP_COUNT=$(grep -v '^$' "${PROC_DIR}/03_Active_TCP_connections.txt" | grep -v "SKIPPED" | wc -l)

    echo "  <h3>/proc &amp; Process Artifacts</h3>" >> "$REPORT_FILE"
    echo "  <ul>" >> "$REPORT_FILE"
    if [ "$PR_FIND" -gt 0 ]; then
      echo "    <li>Deleted‐binary processes found: ${PR_FIND}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No deleted‐binary processes detected</li>" >> "$REPORT_FILE"
    fi
    if [ "$OF_COUNT" -gt 0 ]; then
      echo "    <li>Open files detected: ${OF_COUNT}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No open files found</li>" >> "$REPORT_FILE"
    fi
    if [ "$TCP_COUNT" -gt 0 ]; then
      echo "    <li>Active TCP sockets detected: ${TCP_COUNT}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No active TCP connections found</li>" >> "$REPORT_FILE"
    fi
    echo "  </ul>" >> "$REPORT_FILE"
  fi

  # FS section findings:
  if [[ " $SECTIONS " == *" fs "* ]]; then
    local FS_DIR="${ROOT_DIR}/03_filesystem_checks"
    local SUID_COUNT MOD_COUNT
    SUID_COUNT=$(grep -v '^$' "${FS_DIR}/01_SUID_SGID_files.txt" | grep -v "SKIPPED" | wc -l)
    MOD_COUNT=$(grep -v '^$' "${FS_DIR}/02_Recently_modified_files_last_24h.txt" | grep -v "SKIPPED" | wc -l)

    echo "  <h3>Filesystem Integrity &amp; Attributes</h3>" >> "$REPORT_FILE"
    echo "  <ul>" >> "$REPORT_FILE"
    if [ "$SUID_COUNT" -gt 0 ]; then
      echo "    <li>SUID/SGID files found: ${SUID_COUNT}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No SUID/SGID files found</li>" >> "$REPORT_FILE"
    fi
    if [ "$MOD_COUNT" -gt 0 ]; then
      echo "    <li>Recently modified files (past 24h) detected: ${MOD_COUNT}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No recently modified files in the last 24 hours</li>" >> "$REPORT_FILE"
    fi
    echo "  </ul>" >> "$REPORT_FILE"
  fi

  # Network section findings:
  if [[ " $SECTIONS " == *" network "* ]]; then
    local NET_DIR="${ROOT_DIR}/04_network_checks"
    local SOCK_COUNT FW_COUNT SS_COUNT
    SOCK_COUNT=$(grep -v '^$' "${NET_DIR}/01_Open_listening_sockets.txt" | grep -v "SKIPPED" | wc -l)
    FW_COUNT=$(grep -v '^$' "${NET_DIR}/02_Firewall_rules.txt" | grep -v "SKIPPED" | wc -l)
    SS_COUNT=$(grep -v '^$' "${NET_DIR}/03_Socket_stats.txt" | grep -v "SKIPPED" | wc -l)

    echo "  <h3>Network Indicators</h3>" >> "$REPORT_FILE"
    echo "  <ul>" >> "$REPORT_FILE"
    if [ "$SOCK_COUNT" -gt 0 ]; then
      echo "    <li>Listening sockets found: ${SOCK_COUNT}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No listening sockets detected</li>" >> "$REPORT_FILE"
    fi
    if [ "$FW_COUNT" -gt 0 ]; then
      echo "    <li>Firewall rules present</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No firewall rules found</li>" >> "$REPORT_FILE"
    fi
    if [ "$SS_COUNT" -gt 0 ]; then
      echo "    <li>Socket statistics available: ${SS_COUNT} entries</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No socket statistics data</li>" >> "$REPORT_FILE"
    fi
    echo "  </ul>" >> "$REPORT_FILE"
  fi

  # Kernel section findings:
  if [[ " $SECTIONS " == *" kernel "* ]]; then
    local KERNEL_DIR="${ROOT_DIR}/01_kernel_modules"
    local LSMD_COUNT HIDDEN_COUNT EBP_COUNT
    LSMD_COUNT=$(grep -v '^$' "${KERNEL_DIR}/01_List_loaded_kernel_modules.txt" | grep -v "SKIPPED" | wc -l)
    HIDDEN_COUNT=$(grep -v '^$' "${KERNEL_DIR}/04_Detect_hidden_malicious_modules.txt" | grep -v "SKIPPED" | wc -l)
    EBP_COUNT=$(grep -v '^$' "${KERNEL_DIR}/05_Check_for_eBPF_tracing_hooks.txt" | grep -v "SKIPPED" | wc -l)

    echo "  <h3>Kernel &amp; Modules</h3>" >> "$REPORT_FILE"
    echo "  <ul>" >> "$REPORT_FILE"
    if [ "$HIDDEN_COUNT" -gt 0 ]; then
      echo "    <li>Potential hidden/malicious modules detected: ${HIDDEN_COUNT}</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No hidden or malicious modules found</li>" >> "$REPORT_FILE"
    fi
    if [ "$EBP_COUNT" -gt 0 ]; then
      echo "    <li>eBPF/tracing hooks found: ${EBP_COUNT} entries</li>" >> "$REPORT_FILE"
    else
      echo "    <li>No eBPF/tracing hooks present</li>" >> "$REPORT_FILE"
    fi
    echo "  </ul>" >> "$REPORT_FILE"
  fi

  # You can add similar per‐section blocks for users, logs, etc., if desired.

  cat <<EOF >> "$REPORT_FILE"
  <h2>Notable Failures</h2>
EOF

  if [ -z "$FAILED_LIST" ]; then
    cat <<EOF >> "$REPORT_FILE"
  <p>No checks failed.</p>
EOF
  else
    cat <<EOF >> "$REPORT_FILE"
  <ul>
EOF
    while IFS= read -r line; do
      echo "    <li><code>${line}</code></li>" >> "$REPORT_FILE"
    done <<< "$FAILED_LIST"
    cat <<EOF >> "$REPORT_FILE"
  </ul>
EOF
  fi

  cat <<EOF >> "$REPORT_FILE"
  <h2>Skipped Checks (Commented Out or Missing Utility)</h2>
EOF

  if [ -z "$SKIPPED_LIST" ]; then
    cat <<EOF >> "$REPORT_FILE"
  <p>No checks were skipped.</p>
EOF
  else
    cat <<EOF >> "$REPORT_FILE"
  <ul>
EOF
    while IFS= read -r line; do
      echo "    <li><code>${line}</code></li>" >> "$REPORT_FILE"
    done <<< "$SKIPPED_LIST"
    cat <<EOF >> "$REPORT_FILE"
  </ul>
EOF
  fi

  cat <<EOF >> "$REPORT_FILE"
  <p><a href="index.html">Back to Root Index</a></p>
</body>
</html>
EOF

  echo "Created executive summary report: ${REPORT_FILE}"
}

###############################################################################
###  LAUNCH EACH REQUESTED SECTION IN PARALLEL (SHOWING PROGRESS)
###############################################################################
echo
TOTAL_SECTIONS=$(echo "$SECTIONS" | wc -w)
CUR_SECTION=0
PIDS=""

for SECTION in $SECTIONS; do
  CUR_SECTION=$((CUR_SECTION + 1))
  SECTION_TITLE="$(display_title "$SECTION")"
  echo "Overall progress: Section ${CUR_SECTION}/${TOTAL_SECTIONS} - '${SECTION_TITLE}'"

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
  PIDS="${PIDS} $!"
done

for pid in $PIDS; do
  wait "$pid" || echo "WARNING: One background job (PID $pid) exited with an error."
done

generate_master_index

if [ "$EXPORT_REPORT" -eq 1 ]; then
  generate_executive_report
fi

###############################################################################
###  GENERATE FINAL EXPORTS (JSON, CSV, TAR, ZIP)
###############################################################################
if [ "$EXPORT_CSV" -eq 1 ]; then
  CSV_FILE="${ROOT_DIR}/report_summary.csv"
  echo "\"Section\",\"Technique\",\"TTP\",\"Command\",\"Status\"" > "$CSV_FILE"
  cat "$CSV_TMP" >> "$CSV_FILE"
  echo "Created CSV summary: ${CSV_FILE}"
fi

if [ "$EXPORT_JSON" -eq 1 ]; then
  JSON_FILE="${ROOT_DIR}/report_summary.json"
  {
    echo "["
    sed '$s/,$//' "$JSON_TMP"
    echo "]"
  } > "$JSON_FILE"
  echo "Created JSON summary: ${JSON_FILE}"
fi

if [ "$EXPORT_TAR" -eq 1 ]; then
  TAR_FILE="${ROOT_DIR}.tar.gz"
  tar -czf "$TAR_FILE" "$ROOT_DIR"
  echo "Created TAR archive: ${TAR_FILE}"
fi

if [ "$EXPORT_ZIP" -eq 1 ]; then
  ZIP_FILE="${ROOT_DIR}.zip"
  (cd "$(dirname "$ROOT_DIR")" && zip -rq "$(basename "$ZIP_FILE")" "$(basename "$ROOT_DIR")")
  echo "Created ZIP archive: ${ZIP_FILE}"
fi

rm -f "$JSON_TMP" "$CSV_TMP"

echo
echo "Scan complete. Output directory: ${ROOT_DIR}"
exit 0