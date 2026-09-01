# LBT - Linux Backdoor Triage Collector

A read-only Linux live-response collector focused on common persistence and backdoor mechanisms.

The tool gathers evidence into a timestamped directory. It does **not** install packages, make network requests, restart services, or modify the investigated configuration.

> Live response is not forensically neutral: executing commands can change volatile state and produce logs. If kernel/rootkit compromise is strongly suspected, validate from trusted media or an offline acquisition.

## Checks

* System context
* Accounts and privileged groups
* SSH configuration, keys, `sshrc`, and key options
* PAM configuration and modules
* systemd services, timers, sockets, user units, and generators
* Cron and `at`
* Shell/startup persistence
* Dynamic loader / `LD_PRELOAD`
* Package integrity and critical-file hashes
* SUID/SGID and Linux capabilities
* Running processes and deleted executables
* Network listeners and connections
* Kernel modules and eBPF
* Containers
* Authentication/timeline artifacts
* Detection of locally installed complementary tools
* Optional full-mode recent-file, temp executable, and webshell scans

## Usage

Make the script executable:

```bash
chmod +x linux_backdoor_triage.sh
```

Run the default quick collection:

```bash
sudo ./linux_backdoor_triage.sh
```

Run selected modules:

```bash
sudo ./linux_backdoor_triage.sh --check ssh,pam,systemd
```

List available modules:

```bash
./linux_backdoor_triage.sh --list-checks
```

Run extended scans and use a 14-day lookback window:

```bash
sudo ./linux_backdoor_triage.sh --full --since-days 14
```

Write evidence under a specific parent directory:

```bash
sudo ./linux_backdoor_triage.sh \
  --full \
  --since-days 14 \
  --output /mnt/evidence
```

## Options

| Option           | Description                                                                     |
| ---------------- | ------------------------------------------------------------------------------- |
| `--full`         | Adds slower recent-file, temporary-file, and web-root scans.                    |
| `--since-days N` | Sets the lookback window used by recent-file and journal checks. Default: `30`. |
| `--output DIR`   | Parent directory for the generated evidence directory. Default: `/tmp`.         |
| `--check LIST`   | Runs only selected comma-separated modules.                                     |
| `--list-checks`  | Lists valid module names.                                                       |
| `-h`, `--help`   | Shows usage information.                                                        |

## Evidence output

A run creates a directory similar to:

```text
/tmp/linux-backdoor-triage_server01_20260831T190000Z_a1B2c3/
```

Evidence is separated by module and includes command metadata and exit status. A `SHA256SUMS` manifest is created after collection finishes.

Verify the output afterward with:

```bash
cd /path/to/evidence
sha256sum -c SHA256SUMS
```

## Remote execution

For convenience, a raw GitHub version can be piped to Bash:

```bash
curl -fsSL https://raw.githubusercontent.com/4legoria/lbt/main/linux_backdoor_triage.sh | sudo bash
```

Arguments can be passed with `bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/4legoria/lbt/main/linux_backdoor_triage.sh \
  | sudo bash -s -- --check ssh,pam,systemd
```

For incident-response work, prefer pinning a tag or commit and downloading/verifying the script before privileged execution rather than executing a mutable `main` branch directly.

`LBT` is intentionally a **collector**. Its output and heuristic matches are evidence for investigation, not automatic proof of compromise.

**Use your brain.**

## Complementary tools

Depending on the investigation, useful complementary tooling can include:

* UAC for broader Unix-like artifact collection
* Lynis for configuration auditing and hardening
* osquery or Velociraptor for fleet hunting and repeatable queries
* chkrootkit/rkhunter as supplementary indicators, not definitive verdicts
