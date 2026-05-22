# Installation

> Get from `git clone` to a rendered `report.html` in about 3 minutes.
>
> **DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0**

---

## Prerequisites

| Tool | Why | Verify |
|------|-----|--------|
| **Python 3.10+** | The `ir-agent` CLI + telemetry tools | `python --version` |
| **Docker + Docker Compose** | The 5 enrichment microservices | `docker --version` / `docker compose version` |
| **Anthropic API key** | Drives the Claude tool-use loop (`claude-opus-4-7`) | console.anthropic.com → API Keys |

Optional:

| Tool | Why |
|------|-----|
| VirusTotal API key | Real IOC reputation (free tier OK) |
| AbuseIPDB API key  | Real IP abuse scores (free tier OK) |
| Shodan API key     | Real host posture (paid recommended for IR) |
| AWS credentials    | Live CloudTrail / GuardDuty / VPC flow queries |
| Azure SPN creds    | Live Entra / Sentinel / Graph queries |

The sample-mode walkthrough below works **without any of the optional
items** — only the Anthropic key is needed end-to-end.

---

## 1. Clone

```bash
git clone https://github.com/develgroup/ai-incident-response-agent-toolkit.git
cd ai-incident-response-agent-toolkit
```

---

## 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and at minimum set:

```ini
ANTHROPIC_API_KEY=sk-ant-...
IR_AGENT_MODEL=claude-opus-4-7
```

If you have them, also add:

```ini
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
SHODAN_API_KEY=...
```

Otherwise, the enrichment services start up and return structured `503 — not
configured` responses — the agent sees them as "data unavailable" and routes
around them. The investigation still runs.

---

## 3. Bring up enrichment microservices

```bash
docker compose up -d enrichment-agents
```

This builds and starts 5 containers on local ports `8081–8085`:

| Service | Port |
|---------|------|
| VirusTotal     | http://localhost:8081 |
| AbuseIPDB      | http://localhost:8082 |
| Shodan         | http://localhost:8083 |
| MalwareBazaar  | http://localhost:8084 |
| YARA           | http://localhost:8085 |

Sanity-check each:

```bash
for port in 8081 8082 8083 8084 8085; do
  curl -s "http://localhost:$port/health"; echo
done
```

You should see `{"status":"ok",...}` from each.

---

## 4. Install the Python CLI

```bash
pip install -e .
```

This registers the `ir-agent` console script. Verify:

```bash
ir-agent --help
ir-agent investigate --help
```

---

## 5. Run the demo investigation (sample dataset, no cloud creds needed)

The repo ships with a synthetic AWS breach (leaked IAM key → snapshot
exfiltration to an external account) and a synthetic Azure breach (AiTM
token replay → privileged SPN credential abuse).

```bash
# AWS leaked-key sample
ir-agent investigate \
  --signal alerts/aws-guardduty-cred-exfil.json \
  --sample

# Azure AiTM sample
ir-agent investigate \
  --signal alerts/azure-aitm-token-replay.json \
  --sample
```

The CLI streams progress (`validating... expanding... mapping ATT&CK...`)
and writes:

- `out/report.html` — interactive attack-graph report
- `out/report.json` — machine-readable graph + staged-action payload

Open `out/report.html` in any browser.

---

## 6. Selecting a subset of tools (flags)

```bash
# AWS only, VirusTotal-only enrichment
ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json \
                     --sample --cloud aws --enrich virustotal

# Multiple enrichment providers via short aliases
#   vt = virustotal · ai = abuseipdb · sh = shodan · mb = malwarebazaar
ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json \
                     --sample --enrich vt,ai,sh

# Disable enrichment entirely (telemetry + reasoning only)
ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json \
                     --sample --enrich none
```

| Flag | Default | What it does |
|------|---------|--------------|
| `--cloud` | inferred from signal | Forces AWS / Azure / GCP routing. |
| `--enrich` | `all` | Subset of enrichment providers. Comma list, aliases, `all`, or `none`. |
| `--sample` / `--live` | `--live` | `--sample` reads from `sample-telemetry/` (no cloud calls). |
| `--out` | `./out` | Output directory for `report.html` + `report.json`. |

---

## 7. Run a real investigation

Once you have AWS or Azure credentials wired into `.env`, drop `--sample`
and provide a real Point A signal:

```bash
ir-agent investigate --signal alerts/your-real-signal.json --cloud aws
```

Custom `TenantProfile`s go in `config/tenant.aws.yaml` and
`config/tenant.azure.yaml` (copy the `tenant.example.*.yaml` templates).

---

## 8. Tear down

```bash
docker compose down
```

The Python CLI has no daemon — nothing else to stop.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `docker compose up` fails — port already in use | Edit `docker-compose.yml` to remap ports `8081–8085`. |
| `/health` returns 500 on a service | Check `docker compose logs <service>`. Usually a key-missing path that the latest images already handle gracefully — rebuild with `docker compose build --no-cache <service>`. |
| `ir-agent: command not found` | Re-run `pip install -e .` inside an active virtualenv. |
| `anthropic.AuthenticationError` | `ANTHROPIC_API_KEY` not set or wrong. |
| The report shows `unknown` for many nodes | The model could not get a second source — check enrichment-service logs; this is the two-source rule kicking in correctly. |

---

*Built and maintained by Camilo Fernández · Devel Group · Red Spears Labs ·
https://www.devel.group*
