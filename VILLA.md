# The Devel Group Villa · AI-Driven Incident Response

> A walk-up booth where you reconstruct a cloud breach with AI, walk away
> with the report, and (if you want) build your own dataset and your own
> enrichment dockers on the spot.
>
> **DEVEL GROUP · Red Spears Labs · https://www.devel.group**

---

## What we're showing

The full open-source toolkit from the briefing:

> *"How AI reconstructs the full attack path of a cloud or server breach —
> from initial entry to lateral movement — and turns containment from days
> into minutes."*

In numbers:

| | Before · manual IR | With our toolkit |
|---|---|---|
| Detect → scope → reconstruct → contain | 16 hrs to 2 days | ~2 hours |
| Source for every claim | Analyst memory | Cited log event |
| Attack-path output | Spreadsheet | Causal graph + MITRE map |
| Containment | Decided in a meeting | Pre-staged, awaiting approval |

---

## What you'll do at the villa (≈ 15 minutes)

1. **See the live reconstruction.** We run the leaked-IAM-key sample breach
   in front of you. AI agents pull CloudTrail, enrich the source IP via
   VirusTotal + AbuseIPDB + Shodan, prove the path, and produce a
   `report.html` while you watch.

2. **Take the toolkit home.** Clone
   `github.com/devel-group/ai-incident-response`, `pip install`, and
   `docker compose up`. The 3-command quickstart is documented in
   [INSTALL.md](INSTALL.md).

3. **Run the villa CTF.** Five forensic questions over the generated report.
   Score 5/6 → Devel Group sticker + coffee. Full walkthrough in
   [EXERCISE.md](EXERCISE.md).

4. **Bring your own dataset (optional).** Drop your sanitized CloudTrail,
   GuardDuty, or Entra logs into `sample-telemetry/<cloud>/`, write a
   matching Point A signal in `alerts/`, and re-run. You leave with a
   report on **your** data.

5. **Bring your own dockers (optional).** Add a new enrichment provider
   (CrowdSec, GreyNoise, internal threat-intel API). Four files. The
   orchestrator picks it up on the next run with no agent-side changes.

---

## What you take home

| Artifact | What it is |
|----------|------------|
| `report.html` | An interactive attack-graph report — Executive Summary, Attack Path, MITRE coverage, ranked containment runbook |
| `report.json` | Machine-readable graph (feed into your SOAR / case mgmt / SIEM) |
| The whole repo | Apache-2.0. Yours to fork, extend, ship internally. |
| A CLAUDE.md | So you can drop the repo into [Claude Code](https://claude.com/claude-code) and have the agent already know how to operate it |

---

## What we cover at the villa (talk to us)

Bring questions about:

- **Adapting the toolkit to your tenant** — TenantProfile schema for AWS
  and Azure (`config/tenant.example.*.yaml`).
- **Adding clouds** — GCP specialist agent ships in `agents/gcp-ir.system.md`;
  tool bindings for GCP are in v1.1.
- **Wiring real enrichment APIs** — VirusTotal, AbuseIPDB, Shodan,
  MalwareBazaar, and YARA all ship as Dockerized microservices in
  `enrichment-agents/`. Drop in your keys via `.env` and they go live.
- **The operating contract** — Point A start, two-source rule,
  stage-don't-execute. The deck slide *"It all starts with the system
  prompt"* is now `agents/ir-agent.system.md` in the repo, ~8 KB of
  contract.
- **MITRE ATT&CK coverage** — Every confirmed node is auto-mapped via
  `config/mitre-attack-map.yaml`. Add an event-name → technique entry and
  the graph builder picks it up.
- **Cost and latency** — Adaptive thinking + prompt caching on a ~30 KB
  system prompt. We'll show you the token-usage breakdown live.

---

## Why this matters for your SOC

- **Reconstruction, not detection.** Your SIEM tells you *that* something
  happened. The toolkit tells you the *whole story*, with citations.
- **Defensible reports.** Every node carries its evidence; no hand-wavy
  narrative.
- **Knowledge that compounds.** Each incident becomes a queryable
  attack-graph artifact — the PDF nobody re-reads becomes a graph the next
  agent already knows.
- **Human-in-the-loop by design.** The agent stages containment; a
  responder approves. Nothing destructive runs unattended.

---

## Adoption path (the rule that doesn't change)

| Phase | Weeks | AI owns | Humans own |
|-------|-------|---------|-----------|
| **Assist** | 1–4 | Drafts the timeline; runs enrichment | Verify every node, execute everything |
| **Accelerate** | Months 2–3 | Owns enrichment + graph building | Decisions, approval, execution |
| **Orchestrate** | Month 4+ | Runs full loop, pre-stages containment | Approve at the gate |

> *AI compresses the investigation. Humans still own the irreversible
> decisions.*

---

## Hand-on commitment

We don't pitch it — we **run it for you**. Come to the villa with:

- A laptop (Docker Desktop + Python ≥ 3.10)
- An Anthropic API key (or use ours during the demo)
- Optional: a small sanitized log sample from your own environment

Leave with: a working reconstruction, the repo, and a sticker.

---

## Stay in touch

- **Repo:** github.com/devel-group/ai-incident-response (Apache-2.0)
- **Web:** [www.devel.group](https://www.devel.group)
- **Author:** Camilo Fernández — Founder & CEO, Devel Group · Red Spears Labs

*Built for LATAM banking and fintech, released for the global security
community.*
