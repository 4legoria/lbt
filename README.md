# LBT - Linux Backdoor Triage Collector

Read-only Linux live-response collector for common persistence and backdoor mechanisms.

It does **not** install packages, make network requests, restart services or modify the investigated configuration.

> Live response is not forensically neutral. If you suspect kernel/rootkit compromise, validate from trusted media or an offline acquisition.

## Usage

```bash
sudo ./linux_backdoor_triage.sh
sudo ./linux_backdoor_triage.sh --check ssh,pam,systemd
sudo ./linux_backdoor_triage.sh --full --since-days 14
```

Remote:

```bash
curl -fsSL https://raw.githubusercontent.com/4legoria/lbt/main/linux_backdoor_triage.sh | sudo bash
```

For real IR work, pin a tag/commit and verify the script before privileged execution.

## Export

Human-readable text is the default:

```bash
sudo ./linux_backdoor_triage.sh --format text
```

Structured JSON Lines:

```bash
sudo ./linux_backdoor_triage.sh --format jsonl
```

Both:

```bash
sudo ./linux_backdoor_triage.sh --format both
```

JSONL creates one object per sub-check in `results.jsonl` plus run metadata in `run.json`.

Examples:

```bash
jq -c 'select(.event.module == "ssh")' results.jsonl

jq -r 'select(.lbt.exit_status != 0) |
  [.lbt.check.id, .lbt.exit_status] | @tsv' results.jsonl

jq -r 'select(.lbt.check.id == "02_uid0_accounts") |
  .lbt.output.stdout' results.jsonl
```

## Structured data

LBT structured output uses:

- JSON encoded as UTF-8 and valid under RFC 8259.
- RFC 3339 UTC timestamps.
- One JSON object per line for streaming/`jq`/SIEM/AI ingestion.
- An ECS-compatible envelope (`ecs.version`, `event.*`, `host.*`, `agent.*`) with LBT-specific fields under `lbt.*`.
- Versioned LBT records described with JSON Schema Draft 2020-12.
- SHA-256 evidence manifests.

LBT does **not** claim native OCSF normalization yet. Raw host state is not the same thing as a normalized security event; that mapping belongs in a parser/analyzer layer.

## Output

Text mode groups evidence by domain instead of creating one file per command:

```text
01_system_accounts.txt
02_auth_access.txt
03_persistence.txt
04_integrity_privileges.txt
05_runtime.txt
06_kernel_containers.txt
07_timeline.txt
08_extended_hunt.txt   # --full
09_optional_tools.txt
```

JSONL mode is smaller:

```text
00_summary.txt
00_errors.log
run.json
results.jsonl
SHA256SUMS
```

Verify evidence:

```bash
sha256sum -c SHA256SUMS
```

`LBT` is a **collector**. Output is evidence to investigate, not automatic proof of compromise.

> **Use your brain.**
