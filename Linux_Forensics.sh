#!/bin/sh
#
# linux_forensics_scan.sh v0.1 (section‐level parallel, live features disabled by default)
#
# A modular shell script to perform native Linux/Unix compromise-detection checks,
# organize raw outputs and HTML reports by section, and generate a master HTML index.
# - Each section runs in its own background job when multiple sections are specified.
# - Live memory (AVML/LiME) and disk imaging are disabled by default; see HELP.
# Created by Rishabh Dangwal
#
# Usage:
#   ./linux_forensics_scan.sh --all
#   ./linux_forensics_scan.sh [kernel fs proc network users logs live dfir container persistence timeline]
#
# Disabled-by-default features:
#   * Live RAM dumps (AVML/LiME) and DD-based disk imaging are skipped unless the user explicitly enables them by editing the script.
#
# Version: 0.1

echo "linux_forensics_scan.sh version 0.1 (section-level parallel)"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ROOT_DIR="forensics_output_${TIMESTAMP}"
ALL_SECTIONS="kernel proc fs network users logs live dfir container persistence timeline"

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
  live        Live Memory & Disk Forensics (disabled by default)
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

###############################################################################
###  HTML Header/Footer Templates
###############################################################################
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

###############################################################################
###  Utility Check
###############################################################################
require_util() {
  UTIL_NAME="$1"
  if ! command -v "$UTIL_NAME" >/dev/null 2>&1; then
    SKIP_UTIL=1
    return 1
  fi
  SKIP_UTIL=0
  return 0
}

###############################################################################
###  print_system_info
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
###  run_check (sequential)
###
###  Executes a single check:
###    - Writes raw output to RAW_OUT
###    - Appends an HTML snippet directly to section's index.html
###############################################################################
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
      sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$RAW_OUT" >> "$HTML_FILE"
      echo "Check performed [NO] : Exit code ${RC}"
    else
      sed 's/&/&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$RAW_OUT" >> "$HTML_FILE"
      echo "Check performed [OK]"
    fi
  fi

  echo "</pre>" >> "$HTML_FILE"
}

###############################################################################
###  Data: checks grouped by section (TECH_DESC|TTP|COMMAND)
###############################################################################
kernel_checks="
List loaded kernel modules|T1215|lsmod
Check for kernel taint|T1215|cat /proc/sys/kernel/tainted
Compare lsmod vs /sys/module|T1215|lsmod | tail -n +2 | awk \"{print \\\$1}\" | sort > ${ROOT_DIR}/__tmp1.lst && ls /sys/module | sort > ${ROOT_DIR}/__tmp2.lst && diff -u ${ROOT_DIR}/__tmp1.lst ${ROOT_DIR}/__tmp2.lst && rm -f ${ROOT_DIR}/__tmp1.lst ${ROOT_DIR}/__tmp2.lst
Detect hidden/malicious modules|T1215|lsmod | tail -n +2 | awk \"{print \\\$1}\" | sort > ${ROOT_DIR}/__tmp1.lst && ls /sys/kernel/tracing/available_filter_functions | sed -n \"s/.*\\\\[\\\\([^]]*\\\\)\\\\].*/\\\\1/p\" | sort | uniq > ${ROOT_DIR}/__tmp2.lst && diff -u ${ROOT_DIR}/__tmp1.lst ${ROOT_DIR}/__tmp2.lst && rm -f ${ROOT_DIR}/__tmp1.lst ${ROOT_DIR}/__tmp2.lst
Check for eBPF / tracing hooks|T1215|cat /sys/kernel/debug/tracing/trace 2>/dev/null; cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null
"

proc_checks="
Processes running deleted binaries|T1055|ls -alR /proc/*/exe 2>/dev/null | grep deleted
Memory-only (memfd) file descriptors|T1055|for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\+\"); do ls \"/proc/\${pid}/fd\" 2>/dev/null | grep memfd && echo \"PID: \${pid}\"; done
Deleted mappings in process memory|T1055|for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\+\"); do grep \"(deleted)\" \"/proc/\${pid}/maps\" 2>/dev/null && echo \"PID: \${pid}\"; done
Environment-based injection (LD_PRELOAD)|T1574.002|for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\+\"); do strings \"/proc/\${pid}/environ\" 2>/dev/null | tr \"\\0\" \"\\n\" | grep LD_PRELOAD && echo \"PID: \${pid}\"; done
Mismatched cmdline vs comm|T1036|for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\+\"); do if [ -r \"/proc/\${pid}/cmdline\" ] && [ -r \"/proc/\${pid}/comm\" ]; then CMPL=\$(tr \"\\0\" \" \" < \"/proc/\${pid}/cmdline\"); COMM=\$(cat \"/proc/\${pid}/comm\"); case \"\$CMPL\" in *\"\$COMM\"*) ;; *) echo \"PID: \${pid} | cmdline: \$CMPL | comm: \$COMM\" ;; esac; fi; done
Working directory of processes|T1036|ls -alR /proc/*/cwd 2>/dev/null
Processes running from /tmp or /dev/shm|T1036|ls -alR /proc/*/cwd 2>/dev/null | grep \"/tmp\\|/dev/shm\"
"

fs_checks="
Verify installed RPM files|T1105|rpm -Va | grep '^..5\\.' 2>/dev/null
Verify installed DEB files|T1105|debsums -c 2>/dev/null
Immutable files & directories|T1562.003|lsattr -R / 2>/dev/null | grep ' i '
Find SUID/SGID files|T1543|find / -type f \\( -perm -04000 -o -perm -02000 \\) -exec ls -lg {} \\; 2>/dev/null
Files/dirs with no valid owner/group|T1083|find / \\( -nouser -o -nogroup \\) -exec ls -lg {} \\; 2>/dev/null
Hidden files / Unexpected '.' directories|T1083|find / -type d -name '.*' 2>/dev/null
Bind-mount anomalies & iptables rules|T1562.003|iptables -L -v -n 2>/dev/null; iptables -t nat -L -v -n 2>/dev/null; cat /proc/mounts | grep proc; mount | grep -vE \"(/etc|/proc|/sys|/dev)\"
"

network_checks="
Listening sockets & owner|T1049|ss -plant 2>/dev/null
Map open sockets to processes|T1049|lsof -Pn -i 2>/dev/null
DNS tunneling / Unexpected DNS queries|T1040|tcpdump -i any -n -s0 udp port 53 -c 20
iptables rules & NAT anomalies|T1562.003|iptables -L -v -n 2>/dev/null; iptables -t nat -L -v -n 2>/dev/null
eBPF / XDP programs|T1215|ip link show | grep xdp 2>/dev/null; bpftool prog list 2>/dev/null; bpftool map list 2>/dev/null
"

users_checks="
Look for UID=0 entries|T1087|grep '^.*:x:0:' /etc/passwd
Check SSH authorized_keys files|T1574.002|find /home -name authorized_keys 2>/dev/null
Inspect /etc/sudoers & /etc/sudoers.d/|T1574.002|cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null
Recent login history|T1087|last
Failed login attempts|T1087|lastb
Symlinked or missing history files|T1087|find / -name '.*history' 2>/dev/null | grep null
"

logs_checks="
Binary data injected into logs|T1005|grep '[[:cntrl:]]' /var/log/*.log 2>/dev/null
Auditd execve events|T1005|ausearch -m execve -ts today 2>/dev/null
Inspect systemd journal|T1005|journalctl -S yesterday -U now 2>/dev/null
Log rotation / Missing log files|T1005|ls -al /var/log/*.1 /var/log/*.gz 2>/dev/null
Suspicious cron entries|T1053|ls /etc/cron* /var/spool/cron/crontabs 2>/dev/null
"

# Live checks disabled by default
live_checks="
Dump full RAM (AVML) [disabled]|T1055|echo 'AVML disabled by default'
Dump full RAM (LiME) [disabled]|T1055|echo 'LiME disabled by default'
Process memory snapshot (interactive) [disabled]|T1055|echo 'gcore snapshot disabled by default'
Create disk image locally (interactive) [disabled]|T1005|echo 'dd disabled by default'
Carve filesystem timeline (requires TIMELINE_IMAGE) [disabled]|T1005|echo 'timeline carving disabled by default'
"

dfir_checks="
Check for known rootkits (chkrootkit)|T1215|chkrootkit
Check for known rootkits (rkhunter)|T1215|rkhunter --check --sk
Scan for hidden processes (unhide)|T1057|unhide quick
Static ELF inspection (readelf/strings)|T1036|readelf -h /usr/bin/sshd 2>/dev/null; strings /usr/bin/sshd
YARA scanning for known patterns (yara)|T1215|yara -r /usr/local/share/yara_rules -s /usr/bin/sshd
Strace on process (PID 1)|T1055|strace -f -e execve -p 1 -o ${ROOT_DIR}/strace_pid1.log
List active BPF programs (bpftool)|T1215|bpftool prog list 2>/dev/null
List active BPF maps|T1215|bpftool map list 2>/dev/null
Audit kernel syscall hooks via BPF (tracee-ebpf)|T1215|tracee-ebpf --list
"

container_checks="
List running Docker containers|T1536|docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}'
Check Docker container mounts|T1536|jq '.Mounts' /var/lib/docker/containers/*/config.v2.json 2>/dev/null
Inspect KVM/QEMU VM logs|T1562.003|ls /var/log/libvirt/qemu 2>/dev/null
"

persistence_checks="
Inspect /etc/rc.local|T1547|cat /etc/rc.local 2>/dev/null
List scripts in init directories|T1547|ls /etc/init.d/ /etc/rc*.d/ 2>/dev/null
List systemd unit files and statuses|T1547|systemctl list-unit-files --type=service --state=enabled
Check SSH persistence in root’s home|T1574.002|ls /root/.ssh/authorized_keys 2>/dev/null
Check for hidden cron entries|T1053|grep -R '.' /var/spool/cron/crontabs 2>/dev/null
"

timeline_checks="
Uptime & unexpected reboots|T1050|uptime
Correlate user logins with suspicious times|T1087|last -s -7days
Check for gaps in logs|T1005|journalctl --verify 2>/dev/null
"

###############################################################################
###  run_section: run each check sequentially; section may run in background
###############################################################################
run_section() {
  SECTION="$1"
  CHECKS_VAR="$2"
  SECTION_NAME="$(display_title $SECTION)"
  DIR_NAME="$(section_dir $SECTION)"
  SECTION_DIR="${ROOT_DIR}/${DIR_NAME}"
  HTML_FILE="${SECTION_DIR}/index.html"

  mkdir -p "${SECTION_DIR}"
  html_header "$SECTION_NAME"

  # Retrieve the list and run sequentially
  LIST=$(eval "printf '%s\n' \"\${${CHECKS_VAR}}\"")
  TOTAL_CHECKS=$(echo "$LIST" | grep -c '^[^ ]')
  COUNTER=0

  while IFS='|' read -r TECH_DESC TTP CMD; do
    COUNTER=$((COUNTER + 1))
    echo "    [${SECTION_NAME}] Running check ${COUNTER}/${TOTAL_CHECKS}: ${TECH_DESC}"
    SAFE_DESC="$(echo "$TECH_DESC" | tr ' /' '_' )"
    RAW_OUT="${SECTION_DIR}/$(printf '%02d' "$COUNTER")_${SAFE_DESC}.txt"
    run_check "$TECH_DESC" "$TTP" "$CMD" "$RAW_OUT"
  done <<EOF
$LIST
EOF

  html_footer
  echo "    [${SECTION_NAME}] Completed (${TOTAL_CHECKS}/${TOTAL_CHECKS} checks)."
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
    ul { list-style-type: none; padding: 0; }
    li { margin: 5px 0; }
    .skipped { color: #888; }
  </style>
</head>
<body>
  <h1>Forensics Scan Report</h1>
  <p><strong>Generated:</strong> $(date -u)</p>
  <h2>System Information</h2>
  <pre>${SYSTEM_INFO}</pre>
  <h2>Sections</h2>
  <ul>
EOF

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
###  Argument Parsing & Execution Flow (with section-level parallelism)
###############################################################################
SECTIONS=""
for ARG in "$@"; do
  if [ "$ARG" = "--all" ]; then
    SECTIONS="$ALL_SECTIONS"
    break
  fi
  if echo "$ALL_SECTIONS" | grep -wq "$ARG"; then
    SECTIONS="$SECTIONS $ARG"
  else
    echo "Unknown section: $ARG"
    usage
  fi
done

SECTIONS="$(echo $SECTIONS | tr ' ' '\n' | awk '!x[$0]++' | tr '\n' ' ')"
if echo "$@" | grep -wq -- "--all"; then
  SECTIONS="$ALL_SECTIONS"
fi

print_system_info

TOTAL_SECTIONS=$(echo "$SECTIONS" | wc -w)
CUR_SECTION=0
PIDS=""

for SECTION in $SECTIONS; do
  CUR_SECTION=$((CUR_SECTION + 1))
  SECTION_NAME="$(display_title $SECTION)"
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

# Wait for all section-jobs to finish
for pid in $PIDS; do
  wait "$pid"
done

generate_master_index

echo "Scan complete. Output directory: ${ROOT_DIR}"