#!/usr/bin/env bash
# Linux Backdoor Triage Collector
# Defensive/live-response utility. Read-only with respect to the investigated
# configuration; it only creates files under the selected output directory.
# Run from a trusted copy when possible.

set -u
set -o pipefail
umask 077

VERSION="0.2.0"
SINCE_DAYS=30
MODE="quick"
OUT_BASE="/tmp"
CHECK_FILTER="all"

VALID_CHECKS="system accounts ssh pam systemd cron startup loader integrity privileges processes network kernel containers timeline optional"

usage() {
  cat <<USAGE
Linux Backdoor Triage Collector v${VERSION}

Usage:
  sudo ./linux_backdoor_triage.sh [options]

Options:
  --full              Include slower recent-file, temp-file and web-root scans.
  --since-days N      Look back N days for recent-file/log checks (default: 30).
  --output DIR        Parent directory for the evidence folder (default: /tmp).
  --check LIST        Run only selected modules (comma-separated).
                      Example: --check ssh,pam,systemd
  --list-checks       Show available module names.
  -h, --help          Show this help.

Available checks:
  ${VALID_CHECKS}

Examples:
  sudo ./linux_backdoor_triage.sh
  sudo ./linux_backdoor_triage.sh --check ssh,pam,systemd
  sudo ./linux_backdoor_triage.sh --full --since-days 14 --output /mnt/evidence

Notes:
  - No packages are installed and no network requests are made.
  - Live response changes some volatile state/logging by definition.
  - --full adds broad, slower scans in addition to the selected modules.
  - If kernel/rootkit compromise is strongly suspected, validate offline from
    trusted media rather than trusting only local userland output.
USAGE
}

list_checks() {
  printf '%s\n' $VALID_CHECKS
}

is_valid_check() {
  local wanted="$1"
  local c
  for c in $VALID_CHECKS; do
    [[ "$c" == "$wanted" ]] && return 0
  done
  return 1
}

validate_check_filter() {
  [[ "$CHECK_FILTER" == "all" ]] && return 0

  local item
  local old_ifs="$IFS"
  IFS=','
  for item in $CHECK_FILTER; do
    IFS="$old_ifs"
    [[ -n "$item" ]] || { echo "Empty check name in --check" >&2; exit 2; }
    is_valid_check "$item" || {
      echo "Invalid check: $item" >&2
      echo "Available checks: $VALID_CHECKS" >&2
      exit 2
    }
    IFS=','
  done
  IFS="$old_ifs"
}

check_selected() {
  local wanted="$1"
  [[ "$CHECK_FILTER" == "all" ]] && return 0

  case ",${CHECK_FILTER}," in
    *",${wanted},"*) return 0 ;;
    *) return 1 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      MODE="full"
      shift
      ;;
    --since-days)
      [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -gt 0 ]] || {
        echo "Invalid --since-days (expected a positive integer)" >&2
        exit 2
      }
      SINCE_DAYS="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 && -n "$2" ]] || {
        echo "Missing --output value" >&2
        exit 2
      }
      OUT_BASE="$2"
      shift 2
      ;;
    --check)
      [[ $# -ge 2 && -n "$2" ]] || {
        echo "Missing --check value" >&2
        exit 2
      }
      CHECK_FILTER="$2"
      shift 2
      ;;
    --list-checks)
      list_checks
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

validate_check_filter

TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST_SAFE="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' || true)"
HOST_SAFE="${HOST_SAFE:-unknown-host}"

mkdir -p -- "$OUT_BASE" || {
  echo "Cannot create output parent directory: $OUT_BASE" >&2
  exit 1
}

OUT="$(mktemp -d "${OUT_BASE%/}/linux-backdoor-triage_${HOST_SAFE}_${TS}_XXXXXX")" || {
  echo "Cannot create evidence directory under: $OUT_BASE" >&2
  exit 1
}

MASTER="$OUT/00_summary.txt"
ERRORS="$OUT/00_errors.log"
: >"$MASTER"
: >"$ERRORS"

log() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$MASTER"
}

run_to_file() {
  local name="$1"
  shift
  local file="$OUT/$name"

  (
    printf '# UTC: %s\n' "$(date -u +%FT%TZ)"
    printf '# Command:'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
    local_rc=$?
    printf '\n# Exit status: %s\n' "$local_rc"
    exit "$local_rc"
  ) >"$file" 2>>"$ERRORS" || true
}

run_shell_to_file() {
  local name="$1"
  shift
  local cmd="$*"
  local file="$OUT/$name"

  (
    printf '# UTC: %s\n' "$(date -u +%FT%TZ)"
    printf '# Command: %s\n\n' "$cmd"
    /bin/bash -o pipefail -c "$cmd"
    local_rc=$?
    printf '\n# Exit status: %s\n' "$local_rc"
    exit "$local_rc"
  ) >"$file" 2>>"$ERRORS" || true
}

module_log() {
  log "Running module: $1"
}

check_system() {
  module_log "system"
  run_to_file 01_uname.txt uname -a
  run_to_file 01_uptime.txt uptime
  run_to_file 01_date.txt date --iso-8601=seconds
  run_shell_to_file 01_os_release.txt 'cat /etc/os-release 2>/dev/null || true'
  run_to_file 01_mounts.txt mount
  run_shell_to_file 01_findmnt.txt 'command -v findmnt >/dev/null 2>&1 && findmnt -R || true'
  run_to_file 01_logged_in.txt who -a
}

check_accounts() {
  module_log "accounts"
  run_shell_to_file 02_passwd.txt 'getent passwd'
  run_shell_to_file 02_uid0_accounts.txt "awk -F: '\$3 == 0 {print}' /etc/passwd"
  run_shell_to_file 02_interactive_shells.txt "awk -F: '\$7 !~ /(nologin|false)$/ {print}' /etc/passwd"
  run_shell_to_file 02_privileged_groups.txt 'for g in sudo wheel adm docker lxd libvirt; do getent group "$g" 2>/dev/null; done'
  run_shell_to_file 02_sudoers_findings.txt "grep -RniE 'NOPASSWD|!authenticate|ALL[[:space:]]*=.*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null || true"
  run_shell_to_file 02_account_files_stat.txt 'stat /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true'
}

check_ssh() {
  module_log "ssh"
  run_shell_to_file 03_sshd_effective.txt "if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeys|forcecommand|permituserrc|permituserenvironment|allowusers|allowgroups|port'; fi"
  run_shell_to_file 03_sshd_config_findings.txt "grep -RniE '^[[:space:]]*(Include|Match|AuthorizedKeys|ForceCommand|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitUserRC|PermitUserEnvironment|AllowUsers|AllowGroups|Port)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true"
  run_shell_to_file 03_ssh_files.txt '
while IFS=: read -r user _ uid gid gecos home shell; do
  [ -n "$home" ] || continue
  [ -d "$home/.ssh" ] || continue
  find "$home/.ssh" -xdev -type f \( -name authorized_keys -o -name authorized_keys2 -o -name rc -o -name environment \) \
    -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
done < <(getent passwd)'
  run_shell_to_file 03_authorized_keys_contents.txt '
while IFS=: read -r user _ uid gid gecos home shell; do
  [ -n "$home" ] || continue
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -f "$f" ] || continue
    echo "===== user=$user file=$f ====="
    sed -n "1,240p" "$f"
  done
done < <(getent passwd)'
  run_shell_to_file 03_authorized_keys_options.txt '
while IFS=: read -r user _ uid gid gecos home shell; do
  [ -d "$home/.ssh" ] || continue
  grep -HniE "(^|,)(command|environment|permitopen|permitlisten|tunnel|from)=" "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2" 2>/dev/null || true
done < <(getent passwd)'
  run_shell_to_file 03_global_sshrc.txt 'for f in /etc/ssh/sshrc; do [ -f "$f" ] && { echo "===== $f ====="; stat "$f"; sed -n "1,240p" "$f"; }; done'
}

check_pam() {
  module_log "pam"
  run_shell_to_file 04_pam_suspicious_modules.txt "grep -RniE 'pam_exec|pam_script|pam_permit|pam_python' /etc/pam.d /etc/security 2>/dev/null || true"
  run_shell_to_file 04_pam_config.txt 'for f in /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/su /etc/pam.d/sudo; do [ -f "$f" ] && { echo "===== $f ====="; cat "$f"; }; done'
  run_shell_to_file 04_pam_modules.txt "find /lib /lib64 /usr/lib /usr/lib64 -type f -name 'pam_*.so' -exec stat -c '%A %U:%G %s %y %n' {} \\; 2>/dev/null"
}

check_systemd() {
  module_log "systemd"
  run_shell_to_file 05_systemd_enabled_services.txt 'command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --state=enabled --no-pager || true'
  run_shell_to_file 05_systemd_running_services.txt 'command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --state=running --no-pager || true'
  run_shell_to_file 05_systemd_timers.txt 'command -v systemctl >/dev/null 2>&1 && systemctl list-timers --all --no-pager || true'
  run_shell_to_file 05_systemd_sockets.txt 'command -v systemctl >/dev/null 2>&1 && systemctl list-sockets --all --no-pager || true'
  run_shell_to_file 05_systemd_unit_files.txt '
for d in /etc/systemd /run/systemd /usr/local/lib/systemd /usr/lib/systemd /lib/systemd; do
  [ -d "$d" ] || continue
  find "$d" -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
done
while IFS=: read -r user _ uid gid gecos home shell; do
  [ -d "$home/.config/systemd" ] || continue
  find "$home/.config/systemd" -type f \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
done < <(getent passwd)'
  run_shell_to_file 05_systemd_exec_findings.txt '
for d in /etc/systemd /run/systemd /usr/local/lib/systemd /usr/lib/systemd /lib/systemd; do
  [ -d "$d" ] && grep -RniE "^[[:space:]]*Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=" "$d" 2>/dev/null || true
done
while IFS=: read -r user _ uid gid gecos home shell; do
  [ -d "$home/.config/systemd" ] && grep -RniE "^[[:space:]]*Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=" "$home/.config/systemd" 2>/dev/null || true
done < <(getent passwd)'
  run_shell_to_file 05_systemd_suspicious_paths.txt '
for d in /etc/systemd /run/systemd /usr/local/lib/systemd /usr/lib/systemd /lib/systemd; do
  [ -d "$d" ] && grep -RniE "Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=.*(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/\\.)" "$d" 2>/dev/null || true
done'
  run_shell_to_file 05_systemd_generators.txt '
for d in /etc/systemd/system-generators /run/systemd/system-generators /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators /lib/systemd/system-generators; do
  [ -d "$d" ] || continue
  echo "===== $d ====="
  find "$d" -maxdepth 1 -type f -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
done'
}

check_cron() {
  module_log "cron"
  run_shell_to_file 06_crontab_system.txt 'cat /etc/crontab 2>/dev/null || true; find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -maxdepth 2 -type f -print -exec sed -n "1,220p" {} \; 2>/dev/null'
  run_shell_to_file 06_user_crontabs.txt 'while IFS=: read -r u _; do c=$(crontab -u "$u" -l 2>/dev/null) || continue; echo "===== $u ====="; printf "%s\n" "$c"; done < /etc/passwd'
  run_shell_to_file 06_cron_suspicious.txt "grep -RniE '(@reboot|curl[[:space:]]|wget[[:space:]]|base64|bash[[:space:]]+-c|python|perl|socat|/dev/tcp/|nc[[:space:]])' /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null || true"
  run_shell_to_file 06_at_queue.txt 'command -v atq >/dev/null 2>&1 && atq || true'
}

check_startup() {
  module_log "startup"
  run_shell_to_file 07_startup_files_stat.txt '
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/rc.local; do [ -f "$f" ] && stat -c "%A %U:%G %s %y %n" "$f"; done
find /etc/profile.d /etc/init.d -maxdepth 2 -type f -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
while IFS=: read -r user _ uid gid gecos home shell; do
  for f in "$home/.profile" "$home/.bash_profile" "$home/.bash_login" "$home/.bashrc" "$home/.zshrc"; do
    [ -f "$f" ] && stat -c "%A %U:%G %s %y %n" "$f"
  done
done < <(getent passwd)'
  run_shell_to_file 07_startup_suspicious.txt '
PATTERN="(curl[[:space:]]|wget[[:space:]]|base64|/dev/tcp/|socat|nc[[:space:]]|LD_PRELOAD|nohup|setsid)"
grep -RniE "$PATTERN" /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /etc/rc.local 2>/dev/null || true
while IFS=: read -r user _ uid gid gecos home shell; do
  grep -HniE "$PATTERN" "$home/.profile" "$home/.bash_profile" "$home/.bash_login" "$home/.bashrc" "$home/.zshrc" 2>/dev/null || true
done < <(getent passwd)'
}

check_loader() {
  module_log "loader"
  run_shell_to_file 08_ld_preload.txt 'echo "===== /etc/ld.so.preload ====="; cat /etc/ld.so.preload 2>/dev/null || true; echo; echo "===== loader config ====="; cat /etc/ld.so.conf 2>/dev/null || true; grep -RHn . /etc/ld.so.conf.d 2>/dev/null || true'
  run_shell_to_file 08_ld_environment_findings.txt '
PATTERN="LD_PRELOAD|LD_LIBRARY_PATH"
grep -RniE "$PATTERN" /etc/environment /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc 2>/dev/null || true
while IFS=: read -r user _ uid gid gecos home shell; do
  grep -HniE "$PATTERN" "$home/.profile" "$home/.bash_profile" "$home/.bashrc" "$home/.zshrc" 2>/dev/null || true
done < <(getent passwd)'
}

check_integrity() {
  module_log "integrity"
  run_shell_to_file 09_package_integrity.txt '
if command -v dpkg >/dev/null 2>&1; then
  for p in openssh-server sudo libpam-modules libc6 coreutils procps; do
    dpkg -s "$p" >/dev/null 2>&1 && { echo "===== dpkg -V $p ====="; dpkg -V "$p"; }
  done
elif command -v rpm >/dev/null 2>&1; then
  for p in openssh-server openssh sudo pam glibc coreutils procps-ng; do
    rpm -q "$p" >/dev/null 2>&1 && { echo "===== rpm -V $p ====="; rpm -V "$p"; }
  done
fi'
  run_shell_to_file 09_critical_files_hashes.txt 'for f in /usr/sbin/sshd /usr/bin/ssh /usr/bin/sudo /usr/bin/su /usr/bin/passwd /bin/bash /bin/sh /usr/bin/ps /usr/bin/ss /usr/bin/ls /usr/bin/find; do [ -f "$f" ] && sha256sum "$f"; done'
}

check_privileges() {
  module_log "privileges"
  run_shell_to_file 10_suid_sgid.txt '
scan_mount() {
  local mnt="$1"
  find "$mnt" -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf "%M %u:%g %s %TY-%Tm-%TdT%TH:%TM:%TS %p\n" 2>/dev/null
}
if command -v findmnt >/dev/null 2>&1; then
  while read -r mnt fstype; do
    case "$fstype" in
      proc|sysfs|devtmpfs|devpts|tmpfs|cgroup|cgroup2|overlay|squashfs|nsfs|tracefs|debugfs|securityfs|pstore|efivarfs|mqueue|hugetlbfs|fusectl|configfs|nfs|nfs4|cifs|smb3|sshfs) continue ;;
    esac
    [ -d "$mnt" ] && scan_mount "$mnt"
  done < <(findmnt -rn -o TARGET,FSTYPE)
else
  scan_mount /
fi'
  run_shell_to_file 10_file_capabilities.txt 'if command -v getcap >/dev/null 2>&1; then for d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /dev/shm /root /home; do [ -e "$d" ] && getcap -r "$d" 2>/dev/null; done; fi'
}

check_processes() {
  module_log "processes"
  run_to_file 11_processes.txt ps auxwwf
  run_shell_to_file 11_pstree.txt 'command -v pstree >/dev/null 2>&1 && pstree -alp || true'
  run_shell_to_file 11_deleted_executables.txt "for e in /proc/[0-9]*/exe; do t=\$(readlink \"\$e\" 2>/dev/null) || continue; case \"\$t\" in *' (deleted)') printf '%s -> %s\\n' \"\$e\" \"\$t\";; esac; done"
  run_shell_to_file 11_lsof_deleted.txt 'command -v lsof >/dev/null 2>&1 && lsof +L1 || true'
  run_shell_to_file 11_suspicious_exec_paths.txt "ps -eo pid=,ppid=,user=,etimes=,comm=,args= | grep -E '(/tmp/|/var/tmp/|/dev/shm/|/home/[^ ]+/\\.)' | grep -v 'grep -E' || true"
}

check_network() {
  module_log "network"
  run_shell_to_file 12_ss_listeners.txt 'command -v ss >/dev/null 2>&1 && ss -lntup || true'
  run_shell_to_file 12_ss_connections.txt 'command -v ss >/dev/null 2>&1 && ss -antup || true'
  run_shell_to_file 12_lsof_network.txt 'command -v lsof >/dev/null 2>&1 && lsof -nP -i || true'
}

check_kernel() {
  module_log "kernel"
  run_shell_to_file 13_lsmod.txt 'command -v lsmod >/dev/null 2>&1 && lsmod || cat /proc/modules 2>/dev/null || true'
  run_shell_to_file 13_modules_config.txt 'cat /etc/modules 2>/dev/null || true; grep -RHn . /etc/modules-load.d /etc/modprobe.d 2>/dev/null || true'
  run_shell_to_file 13_kernel_modules_files.txt 'find /lib/modules/$(uname -r) -type f -name "*.ko*" -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null'
  run_shell_to_file 13_ebpf.txt 'if command -v bpftool >/dev/null 2>&1; then echo "===== programs ====="; bpftool prog show; echo "===== maps ====="; bpftool map show; echo "===== links ====="; bpftool link show 2>/dev/null || true; fi; echo "===== pinned ====="; find /sys/fs/bpf -maxdepth 4 -ls 2>/dev/null || true'
}

check_containers() {
  module_log "containers"
  run_shell_to_file 14_containers.txt '
if command -v docker >/dev/null 2>&1; then
  echo "===== docker ps ====="; docker ps -a --no-trunc
  echo "===== docker info ====="; docker info 2>/dev/null
fi
if command -v podman >/dev/null 2>&1; then
  echo "===== podman ps ====="; podman ps -a --no-trunc
fi'
  run_shell_to_file 14_container_socket_mounts.txt 'for f in /proc/[0-9]*/mountinfo; do [ -f "$f" ] || continue; grep -H -E "docker.sock|/var/lib/docker|/var/lib/containers" "$f" 2>/dev/null; done | head -n 500 || true'
}

check_timeline() {
  module_log "timeline"
  run_shell_to_file 15_last.txt 'command -v last >/dev/null 2>&1 && last -ai || true'
  run_shell_to_file 15_lastb.txt 'command -v lastb >/dev/null 2>&1 && lastb -ai || true'
  run_shell_to_file 15_ssh_journal.txt "if command -v journalctl >/dev/null 2>&1; then journalctl --no-pager --since '$SINCE_DAYS days ago' -u ssh -u sshd 2>/dev/null || true; fi"
  run_shell_to_file 15_auth_logs_findings.txt "grep -hEi '(Accepted|Failed password|Invalid user|session opened|sudo:|useradd|usermod)' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 5000 || true"
}

check_full() {
  module_log "full-mode extended scans"
  run_shell_to_file 16_recent_sensitive_files.txt "find /etc /usr/local /opt /root /home -xdev -type f -mtime -$SINCE_DAYS -exec stat -c '%A %U:%G %s %y %n' {} \\; 2>/dev/null"
  run_shell_to_file 16_recent_temp_executables.txt "find /tmp /var/tmp /dev/shm -xdev -type f -mtime -$SINCE_DAYS \\( -perm /111 -o -name '*.so' -o -name '*.ko' \\) -exec stat -c '%A %U:%G %s %y %n' {} \\; 2>/dev/null"
  run_shell_to_file 16_webshell_hunt.txt '
for d in /var/www /srv/www /usr/share/nginx/html /opt; do
  [ -d "$d" ] || continue
  grep -RIlE --include="*.php" --include="*.phtml" --include="*.jsp" --include="*.cgi" --include="*.py" \
    "(eval[[:space:]]*\\(|base64_decode|shell_exec|passthru[[:space:]]*\\(|proc_open|system[[:space:]]*\\()" "$d" 2>/dev/null
done'
}

check_optional() {
  module_log "optional"
  run_shell_to_file 17_optional_tools.txt '
for t in lynis rkhunter chkrootkit osqueryi velociraptor; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "%s: %s\n" "$t" "$(command -v "$t")"
  fi
done'
}

log "Linux Backdoor Triage Collector v$VERSION"
log "Host: $HOST_SAFE"
log "Mode: $MODE | Recent window: $SINCE_DAYS days"
log "Checks: $CHECK_FILTER"
log "Evidence directory: $OUT"
if [[ $EUID -ne 0 ]]; then
  log "WARNING: not running as root; several checks will be incomplete."
fi

check_selected system     && check_system
check_selected accounts   && check_accounts
check_selected ssh        && check_ssh
check_selected pam        && check_pam
check_selected systemd    && check_systemd
check_selected cron       && check_cron
check_selected startup    && check_startup
check_selected loader     && check_loader
check_selected integrity  && check_integrity
check_selected privileges && check_privileges
check_selected processes  && check_processes
check_selected network    && check_network
check_selected kernel     && check_kernel
check_selected containers && check_containers
check_selected timeline   && check_timeline
check_selected optional   && check_optional

if [[ "$MODE" == "full" ]]; then
  check_full
fi

# Final messages must be written before the manifest is generated. After the
# manifest is created, no file inside $OUT should be modified.
log "Collection finished. Review raw output; findings are not automatic proof of compromise."
log "Creating SHA256 evidence manifest."

if command -v sha256sum >/dev/null 2>&1; then
  MANIFEST_TMP="$(mktemp "${TMPDIR:-/tmp}/lbt_manifest_XXXXXX")" || MANIFEST_TMP=""
  if [[ -n "$MANIFEST_TMP" ]] && (
    cd "$OUT" &&
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 |
      sort -z |
      xargs -0 sha256sum
  ) >"$MANIFEST_TMP" 2>/dev/null; then
    mv -- "$MANIFEST_TMP" "$OUT/SHA256SUMS"
  else
    [[ -n "${MANIFEST_TMP:-}" ]] && rm -f -- "$MANIFEST_TMP"
    printf 'WARNING: failed to create SHA256 manifest\n' >&2
  fi
else
  printf 'WARNING: sha256sum not available; manifest not created\n' >&2
fi

printf 'Manifest: %s/SHA256SUMS\n' "$OUT"
printf '%s\n' "$OUT"
