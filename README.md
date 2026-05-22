<p align="center">
  <img src="https://devel.group/wp-content/uploads/2026/02/Logo-Devel.svg" alt="Devel Group" height="64"><br>
  <strong>AI-Driven Incident Response Toolkit</strong><br>
  <em>Intelligence-Driven Cybersecurity · <a href="https://www.devel.group">www.devel.group</a></em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://docs.docker.com/compose/"><img src="https://img.shields.io/badge/docker--compose-required-2496ED?logo=docker&logoColor=white" alt="Docker Compose"></a>
  <a href="https://www.anthropic.com/"><img src="https://img.shields.io/badge/LLM-claude--opus--4--7-D97757" alt="Claude Opus 4.7"></a>
  <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-d63f3f" alt="MITRE ATT&CK mapped"></a>
  <a href="https://github.com/develgroup/ai-incident-response-agent-toolkit/stargazers"><img src="https://img.shields.io/github/stars/develgroup/ai-incident-response-agent-toolkit?style=social" alt="GitHub stars"></a>
</p>

---

> Reconstruct the full attack path of a cloud or host breach — entry to
> exfiltration — as an evidenced, MITRE ATT&CK-mapped causal graph, and
> propose ranked, staged containment actions for a human to approve.
>
> **Open source · Apache-2.0 · Built by Devel Group · Red Spears Labs · Camilo Fernández**

---

## What this is

A complete, runnable AI incident-response toolkit:

- **Master operating contract + cloud / host specialists** —
  `agents/ir-agent.system.md` + `agents/aws-ir.system.md` +
  `agents/azure-ir.system.md` + `agents/gcp-ir.system.md` +
  `agents/windows-ir.system.md`. Every investigation begins at one Point A
  and validates outward with the two-source rule.
- **Enrichment microservices** — Dockerized HTTP wrappers around VirusTotal,
  AbuseIPDB, Shodan, MalwareBazaar, and YARA (`enrichment-agents/`).
- **Cloud + host telemetry tools** — boto3 (AWS), Microsoft Graph / Sentinel
  KQL (Azure), Windows Event Log + Sysmon + Scheduled Tasks + processes
  (Windows). Each tool has a **sample mode** that reads from
  `sample-telemetry/<platform>/*.json` so the entire demo runs without any
  cloud credentials.
- **Attack-graph builder + ATT&CK mapper** — turns confirmed events into a
  causal graph and tags every node with MITRE ATT&CK
  (`ir_agent/graph/`).
- **Staged containment runbooks** — parameterized YAML actions with
  approval gates baked in (`runbooks/aws`, `runbooks/azure`,
  `runbooks/windows`).
- **Dark-themed report renderer** — `report.html` with attack graph,
  executive narrative, ranked runbook, ATT&CK coverage map, and the Devel
  Group brand (`ir_agent/report/`).
- **MCP-ready tool registry** — every tool registered in
  `config/tools.yaml` is one line away from an MCP server manifest.
- **Sample alerts + synthetic breach dataset** — AWS leaked-IAM-key,
  Azure AiTM token replay, Windows PsExec lateral movement.

---

## Documentation

| Doc | What's in it |
|-----|--------------|
| [INSTALL.md](INSTALL.md) | git clone → docker compose up → `ir-agent investigate` in 3 commands. |
| [EXERCISE.md](EXERCISE.md) | Villa mini-CTF — 5 forensic questions over the generated report. |
| [VILLA.md](VILLA.md) | Devel Group villa pitch — what attendees get, how to bring their own dataset. |
| [CLAUDE.md](CLAUDE.md) | Project context for Claude Code — drop this and Claude already knows the toolkit. |

---

## Quickstart — three commands

```bash
git clone https://github.com/develgroup/ai-incident-response-agent-toolkit.git
cd ai-incident-response-agent-toolkit
cp .env.example .env        # add ANTHROPIC_API_KEY (+ optional VT/AbuseIPDB/Shodan keys)

docker compose up -d
pip install -e .

# AWS demo — sample-mode (no credentials needed)
ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json --sample
```

Open `out/report.html` in any browser.

---

## CLI flags

```bash
ir-agent investigate --signal <point_a.json>
                     [--cloud {aws|azure|gcp|windows}]   # forces routing
                     [--enrich <subset>]                  # see below
                     [--sample | --live]                   # default --live
                     [--out <dir>]                         # default ./out
```

`--enrich` values:

| Value | What it enables |
|-------|------------------|
| `all` (default) | All five enrichment providers (VT, AbuseIPDB, Shodan, MalwareBazaar, YARA). |
| `none` | No enrichment — telemetry + reasoning only. |
| `virustotal,abuseipdb,shodan,...` | Comma-separated provider IDs. |
| `vt,ai,sh,mb` | Short aliases (vt=virustotal, ai=abuseipdb, sh=shodan, mb=malwarebazaar). |

Examples:

```bash
# Force AWS, VirusTotal-only enrichment
ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json \
                     --sample --cloud aws --enrich virustotal

# Azure AiTM demo
ir-agent investigate --signal alerts/azure-aitm-token-replay.json --sample

# Windows host (PsExec lateral movement)
ir-agent investigate --signal alerts/windows-psexec-lateral.json --sample
```

---

## Deterministic demo (no Anthropic API key)

The repo ships with two scripts that drive the exact same tool surface the
LLM would — useful for verification, CI, or showing the output without
spending tokens:

```bash
python tools/run_demo.py            # AWS leaked-key → snapshot exfil
python tools/run_demo_windows.py    # Windows PsExec lateral movement
```

Both produce `out/report.html` (or `report_windows.html`) and the matching
`report.json`.

---

## Repository layout

```
ai-incident-response/
├── README.md                  · this file
├── INSTALL.md   EXERCISE.md   VILLA.md   CLAUDE.md
├── LICENSE                    · Apache-2.0
├── docker-compose.yml         · 5 enrichment microservices
├── .env.example               · API keys + tenant pointers
├── pyproject.toml             · the ir-agent CLI package
│
├── agents/                    · System prompts (the operating contract)
│   ├── ir-agent.system.md     · Master orchestrator contract
│   ├── orchestrator.system.md · Cloud/host-routing wrapper
│   ├── aws-ir.system.md       · AWS specialist
│   ├── azure-ir.system.md     · Azure / Entra ID / M365 specialist
│   ├── gcp-ir.system.md       · GCP / Cloud Identity specialist
│   └── windows-ir.system.md   · Windows host specialist
│
├── config/                    · Four-layer stack
│   ├── tools.yaml             · Tool registry (enrichment + telemetry + action)
│   ├── enrichment.yaml        · Enrichment endpoints, rate limits, scoring
│   ├── mitre-attack-map.yaml  · cloud-event / Windows-EventID → ATT&CK
│   ├── tenant.example.aws.yaml
│   ├── tenant.example.azure.yaml
│   └── tenant.example.windows.yaml
│
├── enrichment-agents/         · Dockerized recon / IOC agents
│   ├── virustotal/ abuseipdb/ shodan/ malwarebazaar/ yara/
│
├── ir_agent/                  · Python package (CLI + orchestrator)
│   ├── cli.py                 · ir-agent investigate
│   ├── orchestrator.py        · The tool-use loop
│   ├── config.py              · Loads tenant + tools.yaml + --enrich filter
│   ├── llm/                   · Anthropic SDK wrapper, prompt caching
│   ├── tools/
│   │   ├── enrichment/        · HTTP clients to the docker services
│   │   ├── telemetry/         · boto3 + MS Graph + Windows EventLog
│   │   └── action/            · Staged containment (aws/azure/windows)
│   ├── graph/                 · Attack-graph builder, schema, MITRE mapper
│   └── report/                · Dark-themed Jinja2 report.html
│
├── runbooks/                  · Containment runbook templates
│   ├── aws/                   · revoke-access-key, block-ip-waf, isolate-instance, ...
│   ├── azure/                 · revoke-sessions, remove-app-credential, ...
│   └── windows/               · isolate-host, kill-process, disable-account, ...
│
├── alerts/                    · Sample Point A signals
│   ├── aws-guardduty-cred-exfil.json
│   ├── azure-aitm-token-replay.json
│   └── windows-psexec-lateral.json
│
├── sample-telemetry/          · Synthetic breach dataset
│   ├── aws/                   · cloudtrail / guardduty / vpcflow / iam / config
│   ├── azure/                 · signin / audit / activity / graph / officeactivity
│   └── windows/               · security_events / sysmon / scheduled_tasks / processes
│
└── tools/
    ├── run_demo.py            · AWS deterministic demo
    └── run_demo_windows.py    · Windows deterministic demo
```

---

## The operating contract

Every investigation follows the rules in `agents/ir-agent.system.md`:

1. **Start at Point A.** One alert, one anomaly. Never a blank page.
2. **Two-source rule.** Every node confirmed by two independent sources,
   else `hypothesis`.
3. **Cite everything.** Every node and edge references its log line, event
   ID, or tool response.
4. **MITRE ATT&CK mapped.** Every node tagged with technique ID + name.
5. **Humans own irreversible actions.** Containment is *staged* — the
   agent never auto-executes destructive changes.

---

## Adoption path

| Phase | Weeks | AI owns | Humans own |
|-------|-------|---------|-----------|
| **Assist** | 1–4 | Drafts the timeline; runs enrichment | Verifies every node, executes everything |
| **Accelerate** | Months 2–3 | Owns enrichment + graph building; stages containment | Decisions, approval, execution |
| **Orchestrate** | Month 4+ | Runs full loop, pre-stages containment | Approves at the gate |

> *AI compresses the investigation. Humans still own the irreversible
> decisions.*

---

## Contributing

Pull requests are welcome — for non-trivial changes please open an issue
first to discuss the design. The patterns to keep in mind:

- **`tools.yaml` is the single source of truth.** Every new tool is one
  Python function under `ir_agent/tools/*` plus one entry in
  `config/tools.yaml`.
- **Telemetry tools must support both modes.** Every reader checks
  `in_sample_mode()` and falls back to a `sample-telemetry/<cloud>/*.json`
  fixture so the demo runs without cloud credentials. See
  [`ir_agent/tools/telemetry/aws_cloudtrail.py`](ir_agent/tools/telemetry/aws_cloudtrail.py)
  as the canonical example.
- **Actions are staged, never executed.** Anything under
  `ir_agent/tools/action/*` must return a `proposed-action` object with
  `approval_required: true`. The runbooks under `runbooks/<cloud>/` are
  the only place where the *actual* AWS / Azure / Windows command lives.
- **MITRE coverage matters.** New cloud events or Windows EventIDs need a
  mapping in `config/mitre-attack-map.yaml`.

Before opening a PR, run the deterministic demo and confirm
`out/report.html` still renders cleanly:

```bash
python tools/run_demo.py
```

## Reporting security issues

Please **do not** open public GitHub issues for vulnerabilities in this
toolkit. Email `security@devel.group` with details and we'll respond
within 72h.

## Citation

If this toolkit informs published research, training material, or a
public incident write-up, a citation is appreciated:

```bibtex
@software{devel_ai_ir_toolkit,
  title  = {AI-Driven Incident Response Toolkit},
  author = {Fern{\'a}ndez, Camilo and {Devel Group · Red Spears Labs}},
  year   = {2026},
  url    = {https://github.com/develgroup/ai-incident-response-agent-toolkit},
  note   = {Apache-2.0}
}
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Contributions welcome. Built for
LATAM banking and fintech, released for the global security community.

---

<p align="center">
  <strong>Devel Group · Red Spears Labs</strong><br>
  <em>Intelligence-Driven Cybersecurity</em><br>
  <a href="https://www.devel.group">www.devel.group</a>
</p>
