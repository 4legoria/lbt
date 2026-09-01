#!/usr/bin/env bash
# LBT - Linux Backdoor Triage Collector
# Defensive/live-response utility. Read-only with respect to investigated
# configuration; it only creates files under the selected output directory.

set -u
set -o pipefail
umask 077

VERSION="0.4.0"
SCHEMA_VERSION="1.0.0"
ECS_VERSION="9.5.0"

SINCE_DAYS=30
MODE="quick"
OUT_BASE="/tmp"
CHECK_FILTER="all"
FORMAT="text"
JSON_ENGINE=""
JSON_FAILURES=0
CURRENT_MODULE="core"

VALID_CHECKS="system accounts ssh pam systemd cron startup loader integrity privileges processes network kernel containers timeline optional"

usage() {
  cat <<USAGE
LBT - Linux Backdoor Triage Collector v${VERSION}

Usage:
  sudo ./linux_backdoor_triage.sh [options]

Options:
  --full              Add slower recent-file, temp-file and web-root scans.
  --since-days N      Lookback window for recent-file/log checks (default: 30).
  --output DIR        Parent directory for evidence (default: /tmp).
  --check LIST        Run selected modules, comma-separated.
  --format FORMAT     text, jsonl or both (default: text).
  --list-checks       Show available modules.
  -h, --help          Show this help.

Examples:
  sudo ./linux_backdoor_triage.sh
  sudo ./linux_backdoor_triage.sh --check ssh,pam,systemd
  sudo ./linux_backdoor_triage.sh --format jsonl
  sudo ./linux_backdoor_triage.sh --format both --full --since-days 14

Notes:
  - No packages are installed and no network requests are made.
  - JSONL requires jq or python3 on the investigated host.
  - Live response is not forensically neutral.
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

want_text() {
  [[ "$FORMAT" == "text" || "$FORMAT" == "both" ]]
}

want_jsonl() {
  [[ "$FORMAT" == "jsonl" || "$FORMAT" == "both" ]]
}

detect_json_engine() {
  want_jsonl || return 0

  if command -v jq >/dev/null 2>&1; then
    JSON_ENGINE="jq"
  elif command -v python3 >/dev/null 2>&1; then
    JSON_ENGINE="python3"
  else
    echo "--format $FORMAT requires jq or python3; neither was found." >&2
    exit 3
  fi
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
    --format)
      [[ $# -ge 2 ]] || { echo "Missing --format value" >&2; exit 2; }
      case "$2" in
        text|jsonl|both) FORMAT="$2" ;;
        *) echo "Invalid --format: $2 (expected text, jsonl or both)" >&2; exit 2 ;;
      esac
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
detect_json_engine

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_STARTED_AT="$(date -u +%FT%TZ)"
RUN_STARTED_EPOCH="$(date +%s)"
HOST_SAFE="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' || true)"
HOST_SAFE="${HOST_SAFE:-unknown-host}"
HOST_ARCH="$(uname -m 2>/dev/null || true)"

OS_NAME="Linux"
OS_VERSION=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_NAME="${NAME:-Linux}"
  OS_VERSION="${VERSION_ID:-${VERSION:-}}"
fi

mkdir -p -- "$OUT_BASE" || {
  echo "Cannot create output parent directory: $OUT_BASE" >&2
  exit 1
}

OUT="$(mktemp -d "${OUT_BASE%/}/linux-backdoor-triage_${HOST_SAFE}_${TS}_XXXXXX")" || {
  echo "Cannot create evidence directory under: $OUT_BASE" >&2
  exit 1
}

RUN_ID="$(basename "$OUT")"
MASTER="$OUT/00_summary.txt"
ERRORS="$OUT/00_errors.log"
RESULTS_JSONL="$OUT/results.jsonl"
RUN_JSON="$OUT/run.json"

: >"$MASTER"
: >"$ERRORS"
want_jsonl && : >"$RESULTS_JSONL"

log() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$MASTER"
}

progress() {
  printf '[%s]   -> %s\n' "$(date -u +%FT%TZ)" "$*"
}

group_file_for() {
  case "$1" in
    01_*|02_*) echo "01_system_accounts.txt" ;;
    03_*|04_*) echo "02_auth_access.txt" ;;
    05_*|06_*|07_*|08_*) echo "03_persistence.txt" ;;
    09_*|10_*) echo "04_integrity_privileges.txt" ;;
    11_*|12_*) echo "05_runtime.txt" ;;
    13_*|14_*) echo "06_kernel_containers.txt" ;;
    15_*) echo "07_timeline.txt" ;;
    16_*) echo "08_extended_hunt.txt" ;;
    17_*) echo "09_optional_tools.txt" ;;
    *) echo "99_misc.txt" ;;
  esac
}

ecs_category_for() {
  case "$1" in
    system) echo "host" ;;
    accounts|privileges) echo "iam" ;;
    ssh|pam|timeline) echo "authentication" ;;
    systemd|cron|startup) echo "configuration" ;;
    loader) echo "library" ;;
    integrity) echo "package" ;;
    processes) echo "process" ;;
    network) echo "network" ;;
    kernel) echo "driver" ;;
    containers|optional) echo "host" ;;
    full-mode*) echo "file" ;;
    *) echo "host" ;;
  esac
}

append_error_block() {
  local check_name="$1"
  local err_file="$2"
  [[ -s "$err_file" ]] || return 0
  {
    printf '\n===== %s =====\n' "$check_name"
    cat "$err_file"
  } >>"$ERRORS"
}

append_text_result() {
  local name="$1" command_text="$2" out_tmp="$3"
  local rc="$4" elapsed="$5" started_at="$6" grouped="$7"
  local file="$OUT/$grouped"

  {
    printf '\n======================================================================\n'
    printf 'CHECK: %s\n' "$name"
    printf 'UTC: %s\n' "$started_at"
    printf 'COMMAND: %s\n' "$command_text"
    printf '%s\n\n' '----------------------------------------------------------------------'
    cat "$out_tmp"
    printf '\n----------------------------------------------------------------------\n'
    printf 'EXIT STATUS: %s\n' "$rc"
    printf 'DURATION: %ss\n' "$elapsed"
    printf '======================================================================\n'
  } >>"$file"
}

emit_json_record_jq() {
  local name="$1" command_text="$2" out_tmp="$3" err_tmp="$4"
  local rc="$5" elapsed="$6" started_at="$7" ended_at="$8" grouped="$9"
  local category outcome duration_ns check_id
  category="$(ecs_category_for "$CURRENT_MODULE")"
  [[ "$rc" -eq 0 ]] && outcome="success" || outcome="failure"
  duration_ns=$((elapsed * 1000000000))
  check_id="${name%.txt}"

  jq -cn \
    --rawfile stdout "$out_tmp" \
    --rawfile stderr "$err_tmp" \
    --arg ts "$started_at" \
    --arg end "$ended_at" \
    --arg msg "LBT check $check_id completed" \
    --arg ecs_version "$ECS_VERSION" \
    --arg category "$category" \
    --arg module "$CURRENT_MODULE" \
    --arg outcome "$outcome" \
    --arg host "$HOST_SAFE" \
    --arg tool_version "$VERSION" \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg run_id "$RUN_ID" \
    --arg mode "$MODE" \
    --arg check_id "$check_id" \
    --arg check_name "$name" \
    --arg command "$command_text" \
    --arg group "$grouped" \
    --argjson since_days "$SINCE_DAYS" \
    --argjson exit_status "$rc" \
    --argjson duration "$duration_ns" \
    '{
      "@timestamp": $ts,
      "message": $msg,
      "ecs": {"version": $ecs_version},
      "event": {
        "kind": "state",
        "category": [$category],
        "type": ["info"],
        "action": "collect",
        "module": $module,
        "dataset": ("lbt." + $module),
        "outcome": $outcome,
        "start": $ts,
        "end": $end,
        "duration": $duration
      },
      "host": {"hostname": $host},
      "agent": {"name": "lbt", "type": "lbt", "version": $tool_version},
      "tags": ["linux", "live-response", "backdoor-triage"],
      "lbt": {
        "schema_version": $schema_version,
        "run_id": $run_id,
        "mode": $mode,
        "since_days": $since_days,
        "check": {"id": $check_id, "name": $check_name},
        "command": $command,
        "exit_status": $exit_status,
        "output": {
          "group": $group,
          "stdout": $stdout,
          "stderr": $stderr
        }
      }
    }' >>"$RESULTS_JSONL"
}

emit_json_record_python() {
  local name="$1" command_text="$2" out_tmp="$3" err_tmp="$4"
  local rc="$5" elapsed="$6" started_at="$7" ended_at="$8" grouped="$9"
  local category outcome check_id
  category="$(ecs_category_for "$CURRENT_MODULE")"
  [[ "$rc" -eq 0 ]] && outcome="success" || outcome="failure"
  check_id="${name%.txt}"

  python3 - "$RESULTS_JSONL" "$out_tmp" "$err_tmp" \
    "$started_at" "$ended_at" "$ECS_VERSION" "$category" "$CURRENT_MODULE" \
    "$outcome" "$HOST_SAFE" "$VERSION" "$SCHEMA_VERSION" "$RUN_ID" "$MODE" \
    "$SINCE_DAYS" "$check_id" "$name" "$command_text" "$rc" "$elapsed" "$grouped" <<'PY'
import json, sys
(
    dest, out_file, err_file, started, ended, ecs_version, category, module,
    outcome, host, tool_version, schema_version, run_id, mode, since_days,
    check_id, check_name, command, rc, elapsed, group
) = sys.argv[1:]

with open(out_file, "r", encoding="utf-8", errors="replace") as f:
    stdout = f.read()
with open(err_file, "r", encoding="utf-8", errors="replace") as f:
    stderr = f.read()

obj = {
    "@timestamp": started,
    "message": f"LBT check {check_id} completed",
    "ecs": {"version": ecs_version},
    "event": {
        "kind": "state",
        "category": [category],
        "type": ["info"],
        "action": "collect",
        "module": module,
        "dataset": f"lbt.{module}",
        "outcome": outcome,
        "start": started,
        "end": ended,
        "duration": int(elapsed) * 1_000_000_000,
    },
    "host": {"hostname": host},
    "agent": {"name": "lbt", "type": "lbt", "version": tool_version},
    "tags": ["linux", "live-response", "backdoor-triage"],
    "lbt": {
        "schema_version": schema_version,
        "run_id": run_id,
        "mode": mode,
        "since_days": int(since_days),
        "check": {"id": check_id, "name": check_name},
        "command": command,
        "exit_status": int(rc),
        "output": {"group": group, "stdout": stdout, "stderr": stderr},
    },
}
with open(dest, "a", encoding="utf-8", newline="\n") as f:
    json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    f.write("\n")
PY
}

emit_json_record() {
  case "$JSON_ENGINE" in
    jq) emit_json_record_jq "$@" ;;
    python3) emit_json_record_python "$@" ;;
    *) return 1 ;;
  esac
}

write_check_result() {
  local name="$1" command_text="$2" out_tmp="$3" err_tmp="$4"
  local rc="$5" elapsed="$6" started_at="$7" ended_at="$8"
  local grouped
  grouped="$(group_file_for "$name")"

  if want_text; then
    append_text_result "$name" "$command_text" "$out_tmp" "$rc" "$elapsed" "$started_at" "$grouped"
  fi

  if want_jsonl; then
    if ! emit_json_record "$name" "$command_text" "$out_tmp" "$err_tmp" "$rc" "$elapsed" "$started_at" "$ended_at" "$grouped"; then
      printf 'JSON export failed for %s\n' "$name" >>"$ERRORS"
      JSON_FAILURES=$((JSON_FAILURES + 1))
    fi
  fi

  append_error_block "$name" "$err_tmp"
}

run_to_file() {
  local name="$1"
  shift
  local out_tmp err_tmp started_epoch ended_epoch elapsed rc started_at ended_at command_text

  out_tmp="$(mktemp "$OUT/.stdout_XXXXXX")"
  err_tmp="$(mktemp "$OUT/.stderr_XXXXXX")"
  started_epoch="$(date +%s)"
  started_at="$(date -u +%FT%TZ)"

  printf -v command_text '%q ' "$@"
  command_text="${command_text% }"
  progress "$name"

  "$@" >"$out_tmp" 2>"$err_tmp"
  rc=$?

  ended_epoch="$(date +%s)"
  ended_at="$(date -u +%FT%TZ)"
  elapsed=$((ended_epoch - started_epoch))

  write_check_result "$name" "$command_text" "$out_tmp" "$err_tmp" "$rc" "$elapsed" "$started_at" "$ended_at"
  rm -f -- "$out_tmp" "$err_tmp"
  progress "$name completed [${elapsed}s]"
}

run_shell_to_file() {
  local name="$1"
  shift
  local cmd="$*"
  local out_tmp err_tmp started_epoch ended_epoch elapsed rc started_at ended_at

  out_tmp="$(mktemp "$OUT/.stdout_XXXXXX")"
  err_tmp="$(mktemp "$OUT/.stderr_XXXXXX")"
  started_epoch="$(date +%s)"
  started_at="$(date -u +%FT%TZ)"
  progress "$name"

  /bin/bash -o pipefail -c "$cmd" >"$out_tmp" 2>"$err_tmp"
  rc=$?

  ended_epoch="$(date +%s)"
  ended_at="$(date -u +%FT%TZ)"
  elapsed=$((ended_epoch - started_epoch))

  write_check_result "$name" "$cmd" "$out_tmp" "$err_tmp" "$rc" "$elapsed" "$started_at" "$ended_at"
  rm -f -- "$out_tmp" "$err_tmp"
  progress "$name completed [${elapsed}s]"
}

module_log() {
  CURRENT_MODULE="$1"
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

  # systemctl can occasionally block on a degraded/broken D-Bus/systemd state.
  # Use a bounded timeout when GNU timeout is available.
  run_shell_to_file 05_systemd_enabled_services.txt '
if command -v systemctl >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    timeout 20s systemctl list-unit-files --type=service --state=enabled --no-pager || true
  else
    systemctl list-unit-files --type=service --state=enabled --no-pager || true
  fi
fi'

  run_shell_to_file 05_systemd_running_services.txt '
if command -v systemctl >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    timeout 20s systemctl list-units --type=service --state=running --no-pager || true
  else
    systemctl list-units --type=service --state=running --no-pager || true
  fi
fi'

  run_shell_to_file 05_systemd_timers.txt '
if command -v systemctl >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    timeout 20s systemctl list-timers --all --no-pager || true
  else
    systemctl list-timers --all --no-pager || true
  fi
fi'

  run_shell_to_file 05_systemd_sockets.txt '
if command -v systemctl >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    timeout 20s systemctl list-sockets --all --no-pager || true
  else
    systemctl list-sockets --all --no-pager || true
  fi
fi'

  # Scan only actual unit directories. Do NOT recursively grep all of
  # /run/systemd; runtime trees may contain transient/special objects.
  run_shell_to_file 05_systemd_unit_files.txt '
for d in \
  /etc/systemd/system \
  /run/systemd/system \
  /usr/local/lib/systemd/system \
  /usr/lib/systemd/system \
  /lib/systemd/system \
  /etc/systemd/user \
  /run/systemd/user \
  /usr/local/lib/systemd/user \
  /usr/lib/systemd/user \
  /lib/systemd/user
do
  [ -d "$d" ] || continue
  find "$d" -xdev -type f \
    \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) \
    -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
done

while IFS=: read -r user _ uid gid gecos home shell; do
  [ -d "$home/.config/systemd" ] || continue
  find "$home/.config/systemd" -xdev -type f \
    \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) \
    -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
done < <(getent passwd)'

  run_shell_to_file 05_systemd_exec_findings.txt '
PATTERN="^[[:space:]]*Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)="

scan_units() {
  local d="$1"
  [ -d "$d" ] || return 0
  find "$d" -xdev -type f \
    \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) \
    -print0 2>/dev/null |
    xargs -0 -r grep -HnE "$PATTERN" 2>/dev/null || true
}

for d in \
  /etc/systemd/system \
  /run/systemd/system \
  /usr/local/lib/systemd/system \
  /usr/lib/systemd/system \
  /lib/systemd/system \
  /etc/systemd/user \
  /run/systemd/user \
  /usr/local/lib/systemd/user \
  /usr/lib/systemd/user \
  /lib/systemd/user
do
  scan_units "$d"
done

while IFS=: read -r user _ uid gid gecos home shell; do
  scan_units "$home/.config/systemd"
done < <(getent passwd)'

  run_shell_to_file 05_systemd_suspicious_paths.txt '
PATTERN="Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=.*(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/\\.)"

scan_units() {
  local d="$1"
  [ -d "$d" ] || return 0
  find "$d" -xdev -type f \
    \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) \
    -print0 2>/dev/null |
    xargs -0 -r grep -HnE "$PATTERN" 2>/dev/null || true
}

for d in \
  /etc/systemd/system \
  /run/systemd/system \
  /usr/local/lib/systemd/system \
  /usr/lib/systemd/system \
  /lib/systemd/system \
  /etc/systemd/user \
  /run/systemd/user \
  /usr/local/lib/systemd/user \
  /usr/lib/systemd/user \
  /lib/systemd/user
do
  scan_units "$d"
done

while IFS=: read -r user _ uid gid gecos home shell; do
  scan_units "$home/.config/systemd"
done < <(getent passwd)'

  run_shell_to_file 05_systemd_generators.txt '
for d in \
  /etc/systemd/system-generators \
  /run/systemd/system-generators \
  /usr/local/lib/systemd/system-generators \
  /usr/lib/systemd/system-generators \
  /lib/systemd/system-generators
do
  [ -d "$d" ] || continue
  echo "===== $d ====="
  find "$d" -maxdepth 1 -xdev -type f \
    -exec stat -c "%A %U:%G %s %y %n" {} \; 2>/dev/null
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


log "LBT - Linux Backdoor Triage Collector v$VERSION"
log "Host: $HOST_SAFE"
log "Mode: $MODE | Recent window: $SINCE_DAYS days"
log "Checks: $CHECK_FILTER"
log "Format: $FORMAT${JSON_ENGINE:+ | JSON engine: $JSON_ENGINE}"
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

RUN_ENDED_AT="$(date -u +%FT%TZ)"
RUN_ENDED_EPOCH="$(date +%s)"
RUN_ELAPSED=$((RUN_ENDED_EPOCH - RUN_STARTED_EPOCH))

log "Collection finished. Findings are evidence for review, not automatic proof of compromise."
if want_jsonl && [[ "$JSON_FAILURES" -gt 0 ]]; then
  log "WARNING: $JSON_FAILURES JSON record(s) failed to export."
fi

write_run_json_jq() {
  local outcome="success"
  [[ "$JSON_FAILURES" -eq 0 ]] || outcome="failure"

  jq -cn \
    --arg ts "$RUN_STARTED_AT" \
    --arg end "$RUN_ENDED_AT" \
    --arg ecs_version "$ECS_VERSION" \
    --arg host "$HOST_SAFE" \
    --arg arch "$HOST_ARCH" \
    --arg os_name "$OS_NAME" \
    --arg os_version "$OS_VERSION" \
    --arg tool_version "$VERSION" \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg run_id "$RUN_ID" \
    --arg mode "$MODE" \
    --arg checks "$CHECK_FILTER" \
    --arg format "$FORMAT" \
    --arg json_engine "$JSON_ENGINE" \
    --arg evidence_dir "$OUT" \
    --arg outcome "$outcome" \
    --argjson since_days "$SINCE_DAYS" \
    --argjson duration "$((RUN_ELAPSED * 1000000000))" \
    --argjson json_failures "$JSON_FAILURES" \
    '{
      "@timestamp": $ts,
      "ecs": {"version": $ecs_version},
      "event": {
        "kind": "state",
        "category": ["host"],
        "type": ["info"],
        "action": "collection",
        "module": "lbt",
        "dataset": "lbt.run",
        "outcome": $outcome,
        "start": $ts,
        "end": $end,
        "duration": $duration
      },
      "host": {"hostname": $host, "architecture": $arch},
      "os": {"name": $os_name, "version": $os_version, "type": "linux"},
      "agent": {"name": "lbt", "type": "lbt", "version": $tool_version},
      "lbt": {
        "schema_version": $schema_version,
        "run_id": $run_id,
        "mode": $mode,
        "since_days": $since_days,
        "checks": $checks,
        "format": $format,
        "json_engine": $json_engine,
        "json_failures": $json_failures,
        "evidence_directory": $evidence_dir,
        "records_file": "results.jsonl"
      }
    }' >"$RUN_JSON"
}

write_run_json_python() {
  python3 - "$RUN_JSON" "$RUN_STARTED_AT" "$RUN_ENDED_AT" "$ECS_VERSION" \
    "$HOST_SAFE" "$HOST_ARCH" "$OS_NAME" "$OS_VERSION" "$VERSION" "$SCHEMA_VERSION" \
    "$RUN_ID" "$MODE" "$SINCE_DAYS" "$CHECK_FILTER" "$FORMAT" "$JSON_ENGINE" \
    "$JSON_FAILURES" "$OUT" "$RUN_ELAPSED" <<'PY'
import json, sys
(
    dest, started, ended, ecs_version, host, arch, os_name, os_version,
    tool_version, schema_version, run_id, mode, since_days, checks, fmt,
    json_engine, json_failures, evidence_dir, elapsed
) = sys.argv[1:]

failures = int(json_failures)
obj = {
    "@timestamp": started,
    "ecs": {"version": ecs_version},
    "event": {
        "kind": "state",
        "category": ["host"],
        "type": ["info"],
        "action": "collection",
        "module": "lbt",
        "dataset": "lbt.run",
        "outcome": "success" if failures == 0 else "failure",
        "start": started,
        "end": ended,
        "duration": int(elapsed) * 1_000_000_000,
    },
    "host": {"hostname": host, "architecture": arch},
    "os": {"name": os_name, "version": os_version, "type": "linux"},
    "agent": {"name": "lbt", "type": "lbt", "version": tool_version},
    "lbt": {
        "schema_version": schema_version,
        "run_id": run_id,
        "mode": mode,
        "since_days": int(since_days),
        "checks": checks,
        "format": fmt,
        "json_engine": json_engine,
        "json_failures": failures,
        "evidence_directory": evidence_dir,
        "records_file": "results.jsonl",
    },
}
with open(dest, "w", encoding="utf-8", newline="\n") as f:
    json.dump(obj, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
}

if want_jsonl; then
  case "$JSON_ENGINE" in
    jq) write_run_json_jq ;;
    python3) write_run_json_python ;;
  esac
fi

# No evidence file is modified after the manifest is generated.
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
