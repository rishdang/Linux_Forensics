#!/bin/sh
#
# unit_test_for_scan.sh
#
# A unit-test script for linux_forensics_scan.sh v0.1 checks.
# Runs each check command, records status and details to a text file.
# Detects missing utilities (including diff in composite commands).
# Created by Rishabh Dangwal
#
# Usage:
#   chmod +x unit_test_for_scan.sh
#   ./unit_test_for_scan.sh
#
# Output:
#   unit_test_results.txt – one section per check with status and details.

OUTPUT="unit_test_results.txt"
: > "$OUTPUT"

log_result() {
  SECTION="$1"
  STATUS="$2"
  INFO="$3"
  echo "=== $SECTION ===" >> "$OUTPUT"
  echo "Status: $STATUS" >> "$OUTPUT"
  [ -n "$INFO" ] && echo "Info: $INFO" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
}

run_cmd() {
  SECTION="$1"
  CMD="$2"

  # For composite commands involving diff, check diff utility first
  if echo "$CMD" | grep -q "diff"; then
    if ! command -v diff >/dev/null 2>&1; then
      log_result "$SECTION" "NO" "Utility 'diff' not present"
      return
    fi
  fi

  # Determine primary utility (first token across all lines)
  UTIL="$(printf "%s" "$CMD" | tr '\n' ' ' | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f1)"
  if ! command -v "$UTIL" >/dev/null 2>&1; then
    log_result "$SECTION" "NO" "Utility '$UTIL' not present"
    return
  fi

  # Run the command, capture output and exit code
  TMP_OUT=$(mktemp)
  sh -c "$CMD" > "$TMP_OUT" 2>&1
  RC=$?

  if [ $RC -ne 0 ]; then
    # Non-zero exit: check for permission denied or command not found in output
    if grep -qi "Permission denied" "$TMP_OUT"; then
      log_result "$SECTION" "NO" "Permission denied"
    elif grep -qi "not found" "$TMP_OUT"; then
      MISSING_UTIL=$(grep -i "not found" "$TMP_OUT" | head -n1 | awk '{print $1}')
      log_result "$SECTION" "NO" "Utility '$MISSING_UTIL' not present"
    else
      log_result "$SECTION" "NO" "Exit code $RC"
    fi
  else
    # Succeeded; check if there was any meaningful output
    if [ -s "$TMP_OUT" ]; then
      log_result "$SECTION" "OK" "Output length: $(wc -c < "$TMP_OUT") bytes"
    else
      log_result "$SECTION" "OK" "No output (command succeeded)"
    fi
  fi

  rm -f "$TMP_OUT"
}

echo "Starting unit tests for linux_forensics_scan.sh checks..."
echo "(Results will be written to $OUTPUT)"
echo ""

###############################################################################
# 1. Kernel & Modules
###############################################################################
run_cmd "1.1 List loaded kernel modules" "lsmod"
run_cmd "1.2 Check for kernel taint" "cat /proc/sys/kernel/tainted"
run_cmd "1.3 Compare lsmod vs /sys/module" "bash -c 'lsmod | tail -n +2 | awk \"{print \\$1}\" | sort >/tmp/ut_tmp1.lst; ls /sys/module | sort >/tmp/ut_tmp2.lst; diff -u /tmp/ut_tmp1.lst /tmp/ut_tmp2.lst; rm -f /tmp/ut_tmp1.lst /tmp/ut_tmp2.lst'"
run_cmd "1.4 Detect hidden/malicious modules" "bash -c 'lsmod | tail -n +2 | awk \"{print \\$1}\" | sort >/tmp/ut_tmp1.lst; ls /sys/kernel/tracing/available_filter_functions | sed -n \"s/.*\\[\\([^]]*\\)\\].*/\\1/p\" | sort | uniq >/tmp/ut_tmp2.lst; diff -u /tmp/ut_tmp1.lst /tmp/ut_tmp2.lst; rm -f /tmp/ut_tmp1.lst /tmp/ut_tmp2.lst'"
run_cmd "1.5 Check for eBPF / tracing hooks" "bash -c 'cat /sys/kernel/debug/tracing/trace 2>/dev/null; cat /sys/kernel/debug/tracing/enabled_functions'"

###############################################################################
# 2. /proc & Process Artifacts
###############################################################################
run_cmd "2.1 Processes running deleted binaries" "bash -c 'ls -alR /proc/*/exe 2>/dev/null | grep deleted'"
run_cmd "2.2 Memory-only (‘memfd’) file descriptors" "bash -c 'for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\\+\"); do ls \"/proc/\${pid}/fd\" 2>/dev/null | grep memfd && echo \"PID: \${pid}\"; done'"
run_cmd "2.3 Deleted mappings in memory" "bash -c 'for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\\+\"); do grep \"(deleted)\" \"/proc/\${pid}/maps\" 2>/dev/null && echo \"PID: \${pid}\"; done'"
run_cmd "2.4 Environment-based injection (LD_PRELOAD)" "bash -c 'for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\\+\"); do strings \"/proc/\${pid}/environ\" 2>/dev/null | tr \"\\0\" \"\\n\" | grep LD_PRELOAD && echo \"PID: \${pid}\"; done'"
run_cmd "2.5 Mismatched cmdline vs comm" "bash -c 'for pid in \$(ls /proc 2>/dev/null | grep \"^[0-9]\\+\"); do if [ -r \"/proc/\${pid}/cmdline\" ] && [ -r \"/proc/\${pid}/comm\" ]; then CMPL=\$(tr \"\\0\" \" \" < \"/proc/\${pid}/cmdline\"); COMM=\$(cat \"/proc/\${pid}/comm\"); case \"\$CMPL\" in *\"\$COMM\"*) ;; *) echo \"PID: \${pid} | cmdline: \$CMPL | comm: \$COMM\" ;; esac; fi; done'"
run_cmd "2.6 Working directory of processes" "bash -c 'ls -alR /proc/*/cwd 2>/dev/null'"
run_cmd "2.7 Processes from /tmp or /dev/shm" "bash -c 'ls -alR /proc/*/cwd 2>/dev/null | grep \"/tmp\\|/dev/shm\"'"

###############################################################################
# 3. Filesystem Integrity & Attributes
###############################################################################
run_cmd "3.1 Verify installed RPM files" "bash -c 'rpm -Va 2>/dev/null | grep \"^..5\\.\"'"
run_cmd "3.2 Verify installed DEB files" "debsums -c 2>/dev/null"
run_cmd "3.3 Immutable files & directories" "bash -c 'lsattr -R / 2>/dev/null | grep i'"
run_cmd "3.4 Find SUID/SGID files" "bash -c 'find / -type f \\( -perm -04000 -o -perm -02000 \\) -exec ls -lg {} \\; 2>/dev/null'"
run_cmd "3.5 Files/dirs with no valid owner/group" "bash -c 'find / \\( -nouser -o -nogroup \\) -exec ls -lg {} \\; 2>/dev/null'"
run_cmd "3.6 Hidden files / Unexpected '.' directories" "bash -c 'find / -type d -name \".*\" 2>/dev/null'"
run_cmd "3.7 Bind-mount anomalies & iptables rules" "bash -c 'iptables -L -v -n 2>/dev/null; iptables -t nat -L -v -n 2>/dev/null; cat /proc/mounts | grep proc; mount | grep -vE \"(/etc|/proc|/sys|/dev)\"'"

###############################################################################
# 4. Network Indicators
###############################################################################
run_cmd "4.1 Listening sockets & owner" "ss -plant 2>/dev/null"
run_cmd "4.2 Map open sockets to processes" "lsof -Pn -i 2>/dev/null"
run_cmd "4.3 DNS tunneling / Unexpected DNS queries" "tcpdump -i any -n -s0 udp port 53 -c 20"
run_cmd "4.4 iptables rules & NAT anomalies" "bash -c 'iptables -L -v -n 2>/dev/null; iptables -t nat -L -v -n 2>/dev/null'"
run_cmd "4.5 eBPF / XDP programs" "bash -c 'ip link show | grep xdp 2>/dev/null; bpftool prog list 2>/dev/null; bpftool map list 2>/dev/null'"

###############################################################################
# 5. User Accounts & Authentication
###############################################################################
run_cmd "5.1 Look for UID=0 entries" "grep '^.*:x:0:' /etc/passwd"
run_cmd "5.2 Check SSH authorized_keys files" "find /home -name authorized_keys 2>/dev/null"
run_cmd "5.3 Inspect /etc/sudoers & /etc/sudoers.d/" "bash -c 'cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d/ 2>/dev/null'"
run_cmd "5.4 Recent login history" "last"
run_cmd "5.5 Failed login attempts" "lastb"
run_cmd "5.6 Symlinked or missing history files" "bash -c 'find / -name \".*history\" 2>/dev/null | grep null'"

###############################################################################
# 6. System Logs & Audit Trails
###############################################################################
run_cmd "6.1 Binary data injected into logs" "grep '[[:cntrl:]]' /var/log/*.log 2>/dev/null"
run_cmd "6.2 Auditd execve events" "ausearch -m execve -ts today 2>/dev/null"
run_cmd "6.3 Inspect systemd journal" "journalctl -S yesterday -U now 2>/dev/null"
run_cmd "6.4 Log rotation / Missing log files" "ls -al /var/log/*.1 /var/log/*.gz 2>/dev/null"
run_cmd "6.5 Suspicious cron entries" "ls /etc/cron* /var/spool/cron/crontabs 2>/dev/null"

###############################################################################
# 7. Live Memory & Disk Forensics (non-interactive only)
###############################################################################
run_cmd "7.1 Dump full RAM (AVML)" "avml /tmp/ut_mem_${TIMESTAMP}.dmp"
run_cmd "7.2 Dump full RAM (LiME)" "insmod lime.ko path=/tmp/ut_mem_${TIMESTAMP}.lime format=lime"
log_result "7.3 Process memory snapshot" "SKIPPED" "Interactive"
log_result "7.4 Create disk image locally" "SKIPPED" "Interactive"
log_result "7.5 Carve filesystem timeline" "SKIPPED" "Interactive or requires TIMELINE_IMAGE"

###############################################################################
# 8. CLI & DFIR Tools
###############################################################################
run_cmd "8.1 Check for known rootkits (chkrootkit)" "chkrootkit"
run_cmd "8.2 Check for known rootkits (rkhunter)" "rkhunter --check --sk"
run_cmd "8.3 Scan for hidden processes (unhide)" "unhide quick"
run_cmd "8.4 Static ELF inspection (readelf / strings)" "bash -c 'readelf -h /usr/bin/sshd 2>/dev/null; strings /usr/bin/sshd'"
run_cmd "8.5 YARA scanning for known patterns (yara)" "yara -r /usr/local/share/yara_rules -s /usr/bin/sshd"
run_cmd "8.6 Strace on process (PID 1)" "strace -f -e execve -p 1 -o /tmp/ut_strace_pid1.log"
run_cmd "8.7 List active BPF programs (bpftool)" "bpftool prog list 2>/dev/null"
run_cmd "8.8 List active BPF maps" "bpftool map list 2>/dev/null"
run_cmd "8.9 Audit kernel syscall hooks via BPF (tracee-ebpf)" "tracee-ebpf --list"

###############################################################################
# 9. Container & VM Indicators
###############################################################################
run_cmd "9.1 List running Docker containers" "docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}'"
run_cmd "9.2 Check Docker container mounts" "jq '.Mounts' /var/lib/docker/containers/*/config.v2.json 2>/dev/null"
run_cmd "9.3 Inspect KVM/QEMU VM logs" "ls /var/log/libvirt/qemu 2>/dev/null"

###############################################################################
# 10. Persistence & Backdoor Evidence
###############################################################################
run_cmd "10.1 Inspect /etc/rc.local" "cat /etc/rc.local 2>/dev/null"
run_cmd "10.2 List scripts in init directories" "ls /etc/init.d/ /etc/rc*.d/ 2>/dev/null"
run_cmd "10.3 List systemd unit files and statuses" "systemctl list-unit-files --type=service --state=enabled"
run_cmd "10.4 Check SSH persistence in root’s home" "ls /root/.ssh/authorized_keys 2>/dev/null"
run_cmd "10.5 Check for hidden cron entries" "grep -R '.' /var/spool/cron/crontabs 2>/dev/null"

###############################################################################
# 11. Indicator & Timeline Correlation
###############################################################################
run_cmd "11.1 Uptime & unexpected reboots" "uptime"
run_cmd "11.2 Correlate user logins with suspicious times" "last -s -7days"
run_cmd "11.3 Check for gaps in logs" "journalctl --verify 2>/dev/null"

echo "Unit tests complete. See $OUTPUT for details."