# Changelog — Overnight Session

> Autonomous work session while the user was asleep. Conservative, verifiable
> changes only — no fantasizing, no breaking.
>
> **DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0**

---

## 2026-05-21 · Overnight session

### ✅ Phase 1 — Dark theme + Devel Group logo embedded

- Pulled the Devel Group logo from
  `https://devel.group/wp-content/uploads/2026/02/Logo-Devel.svg`.
- Rewrote `ir_agent/report/templates/report.html.j2` with a dark palette
  (background `#0d0f13`, panels `#14171d`, accent `#e07a4a`/`#ffb56b`),
  Inter font, brand header with embedded logo, and the Devel Group footer
  link to `www.devel.group` + the company tagline.
- Existing report renderer worked unchanged — pure template change.
- Verified: `out/report.html` re-rendered, 28 KB clean.

### ✅ Phase 2 — Branding sweep on 24+ files

- Added `DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0`
  to the docstring of every Python module under `ir_agent/` and every
  enrichment microservice's `app.py` (17 ir_agent + 5 enrichment apps).
- Added the same header line to all AWS + Azure containment runbook YAMLs
  (the Windows ones got it at creation time).
- Added the header to `docker-compose.yml` and `ir_agent/__init__.py`
  (including `__author__` / `__url__` constants).

### ✅ Phase 3 — Windows host specialist (entirely new)

A complete fifth target alongside aws/azure/gcp:

- **`agents/windows-ir.system.md`** — 16 KB specialist contract covering
  Security Event Log + Sysmon + PowerShell + TaskScheduler + WinRM/RDP
  surfaces. 24-hour host-hunt playbook (11 stages from anchor alerts
  through impact). MITRE ATT&CK mapping table for Windows-specific
  techniques (T1003.001 LSASS, T1053.005 Scheduled Task, T1543.003
  Service, T1070.001 log clear, T1021.002 SMB lateral, etc.). Tools +
  staged-containment list. Worked PsExec mini-example.
- **`config/tenant.example.windows.yaml`** — HostFleet profile (domain,
  AD forest, tier-0 servers, jump hosts, EDR vendor, log-collection
  configuration, isolation policy).
- **Telemetry tools** (sample-mode only — live mode marked TODO and
  blocked from autonomous invocation):
  - `ir_agent/tools/telemetry/windows_eventlog.py`
  - `ir_agent/tools/telemetry/windows_sysmon.py`
  - `ir_agent/tools/telemetry/windows_scheduled_tasks.py`
  - `ir_agent/tools/telemetry/windows_processes.py`
- **Staged action tools**: `ir_agent/tools/action/windows_stage.py` with
  isolate_host / kill_process / disable_account / remove_scheduled_task /
  stop_disable_service.
- **Runbook YAMLs** with real PowerShell + EDR API commands:
  - `runbooks/windows/isolate-host.yaml` (Cortex / Defender / CrowdStrike)
  - `runbooks/windows/kill-process.yaml`
  - `runbooks/windows/disable-account.yaml` (with TGT-invalidation note)
  - `runbooks/windows/remove-scheduled-task.yaml`
  - `runbooks/windows/stop-disable-service.yaml`
- **Synthetic breach dataset** (PsExec lateral movement):
  - `sample-telemetry/windows/security_events.json` — 6 events:
    4624 type 10 from external IP, 4672 special privs, 4624 type 3 SMB
    pivot, 4624 type 5 SYSTEM (PSEXESVC), 4698 persistence task, 1102
    log clear.
  - `sample-telemetry/windows/sysmon.json` — 7 events: process tree
    (PSEXESVC → cmd → powershell -enc → update.exe), Sysmon 3 C2,
    Sysmon 10 LSASS access (0x1010), Sysmon 13 Defender exclusion,
    Sysmon 11 file staging.
  - `sample-telemetry/windows/scheduled_tasks.json` — attacker task +
    legitimate baseline for contrast.
  - `sample-telemetry/windows/processes.json` — running snapshot.
- **Point A signal**: `alerts/windows-psexec-lateral.json` (Cortex XDR
  alert).
- **Registry wiring**: 9 new entries in `config/tools.yaml` (4 telemetry
  + 5 staged actions), 14 new entries in `config/mitre-attack-map.yaml`
  (Security event IDs + Sysmon event IDs), `config.py` extended to
  detect Windows signals and accept `--cloud windows`, CLI `--cloud`
  choice extended.
- **Graph builder**: `ir_agent/graph/builder.py` extended to recognize
  `windows.*` tool IDs, parse EventID + Sysmon RecordID, extract
  entities from Windows EventData (TargetUserName, Image, TaskName,
  ProcessGuid), and look up MITRE techniques via the `sysmon-<id>` or
  `<id>` keys.
- **Deterministic demo**: `tools/run_demo_windows.py` produces
  `out/report_windows.html` (45 KB, 18 nodes, 17 edges, **8 MITRE
  techniques**, 5 staged containment actions).

### ✅ Phase 4 — Filter flags + flexibility

(Earlier in the session, but worth surfacing in the overnight summary.)

- `--cloud {aws|azure|gcp|windows}` forces routing.
- `--enrich <subset>` filters enrichment providers — accepts comma-
  separated names (`virustotal,abuseipdb,shodan,malwarebazaar,yara`),
  short aliases (`vt,ai,sh,mb`), `all` (default), or `none`.
- `ir_agent.config.parse_enrich_flag()` rejects unknown providers with
  a clear error message.
- Verified: `--cloud aws --enrich virustotal` returns 11 tools
  (1 enrichment + 5 telemetry + 5 action); `--enrich none` returns
  10 tools (0 enrichment + 5 telemetry + 5 action).

### ✅ Phase 5 — Docs delivered

- `INSTALL.md` — 3-command quickstart + flag reference + troubleshooting.
- `EXERCISE.md` — Villa mini-CTF, 5 scored forensic questions over the
  generated report.
- `VILLA.md` — booth pitch ("clone, run, walk away with your report").
- `CLAUDE.md` — drop-in context file so Claude Code already knows the
  toolkit when someone opens the repo.
- `README.md` — fully refreshed with logo, dark-theme demo screenshot
  cue, flag examples, doc links, repository layout, adoption path,
  Devel Group footer.

### ✅ Phase 6 — Azure deterministic demo

- `tools/run_demo_azure.py` mirrors the AWS + Windows demos: builds the
  AiTM-token-replay trace, produces `out/report_azure.html` (25 KB,
  5 nodes, 2 MITRE techniques: T1098.001 + T1098.003, 5 staged actions).
- All three demos run cleanly in sequence without interference.

---

## Final verification

```
Python files compiled : 47/47 ok
YAML files parsed     : 22/22 ok
JSON files parsed     : 18/18 ok

AWS demo     : 5 nodes  · MITRE T1098.003 / T1530 / T1537 · 5 staged
AZURE demo   : 5 nodes  · MITRE T1098.001 / T1098.003 · 5 staged
WINDOWS demo : 18 nodes · MITRE T1003.001 / T1053.005 / T1059 / T1070.001
               / T1071 / T1074.001 / T1078 / T1562.001 · 5 staged

out/report.html         (28 KB) — AWS leaked-key
out/report_azure.html   (25 KB) — Azure AiTM token replay
out/report_windows.html (45 KB) — Windows PsExec lateral movement
```

Open any of the three in a browser — all use the dark theme with the
Devel Group logo embedded.

---

## What was NOT done (and why)

- **No autonomous "polish subagent" loop.** The user said *sin fantasear*
  ("without fantasizing"). A general-purpose agent given a broad
  "polish 10 iterations" brief is exactly where speculative changes
  happen. Skipped on purpose.
- **No AWS Golden-SAML scenario.** Would have required either
  appending to the existing `sample-telemetry/aws/cloudtrail.json`
  (risk of polluting the leaked-key demo's filtered events) or
  extending the sample loader to support multiple files (refactor
  bigger than the value). The new Windows lateral-movement scenario
  is the complex case for this session.
- **No live GCP tool bindings.** The GCP specialist agent prompt
  already ships (`agents/gcp-ir.system.md`). Live tool bindings would
  require writing `gcp.cloudaudit.query`, `gcp.scc.findings`,
  `gcp.iam.search_iam_policy`, etc. — substantial code I couldn't
  verify against a live GCP project overnight.
- **Live-mode Windows tool execution.** Sample-mode is implemented and
  verified. Live mode would run `Get-WinEvent` via `subprocess` /
  PowerShell on the local host, which would generate real security
  events on **this** machine. Explicitly blocked with a clear error
  message — see `ir_agent/tools/telemetry/windows_eventlog.py`.
- **More aggressive prompt tuning.** The agent system prompts are the
  load-bearing artifact. Changes there should be reviewed by the
  author — left alone.

---

## How to verify everything when you wake up

```bash
# 1. The three deterministic demos (no Anthropic key needed)
python tools/run_demo.py            # AWS leaked-key  → out/report.html
python tools/run_demo_azure.py      # Azure AiTM      → out/report_azure.html
python tools/run_demo_windows.py    # Windows PsExec  → out/report_windows.html

# 2. The CLI with flags (requires ANTHROPIC_API_KEY for the live LLM path)
ir-agent investigate --signal alerts/windows-psexec-lateral.json --sample
ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json \
                     --sample --cloud aws --enrich virustotal

# 3. Docker enrichment is still up — restart if needed
docker compose ps
docker compose up -d
```

---

*Devel Group · Red Spears Labs · Intelligence-Driven Cybersecurity ·
https://www.devel.group · Apache-2.0*
