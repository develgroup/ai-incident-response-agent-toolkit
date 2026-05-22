# Villa Exercise · The Leaked Key

> Hands-on mini-CTF that ships with the toolkit. Clone the repo, run three
> commands, watch an AI reconstruct a real-shape AWS intrusion end to end,
> then answer five forensic questions.
>
> **DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0**

---

## The scenario

You are the on-call analyst for **Acme Corp**. At `2026-05-19 12:14 UTC`,
GuardDuty fires:

```
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
  account: 444455556666 (prod)
  region:  us-east-1
  source:  198.51.100.7
```

That is your **Point A**. Everything else is unknown.

The toolkit's specialist agent reads the alert, reconstructs the full path,
maps every step to MITRE ATT&CK, and produces a ranked containment runbook.
Your job is to follow along, read the generated report, and answer five
questions.

---

## Setup (3 commands — see [INSTALL.md](INSTALL.md) for full details)

```bash
git clone https://github.com/devel-group/ai-incident-response.git
cd ai-incident-response
cp .env.example .env   # add ANTHROPIC_API_KEY (the only required key)

docker compose up -d enrichment-agents
pip install -e .
```

---

## Run the investigation

```bash
ir-agent investigate \
  --signal alerts/aws-guardduty-cred-exfil.json \
  --sample
```

The `--sample` flag tells the telemetry tools to read from
`sample-telemetry/aws/` (a synthetic but realistic breach dataset that ships
with the repo) instead of calling real boto3.

You'll see something like:

```
─── validating... expanding... mapping ATT&CK... (cloud=AWS · enrich=all) ───
[INFO] starting investigation cloud=aws enrich=all sample=True
[INFO] iter=1 stop_reason=tool_use  in=5821 out=482 cache_read=0
[INFO] tool=abuseipdb.check params=['ip']
[INFO] tool=shodan.host    params=['ip']
[INFO] iter=2 stop_reason=tool_use  in=6904 out=388 cache_read=5821
[INFO] tool=aws.cloudtrail.lookup params=['attribute', 'value']
...
[INFO] iter=8 stop_reason=end_turn  in=12044 out=1832 cache_read=11823
─── reconstruction complete · 8 iterations ───
Attack path reconstructed → out/report.html
Machine-readable graph →    out/report.json

5 containment actions staged pending human approval.
```

Open `out/report.html` in any browser.

---

## What you'll see

Six sections in the report:

1. **At a glance** — Cloud, iterations, node count, staged actions.
2. **Executive Summary** — A plain-language narrative of what happened.
3. **Attack Path** — Node-by-node graph from Point A → exfiltration. Each
   node is colored by confidence (`confirmed` / `likely` / `hypothesis`)
   and carries its MITRE ATT&CK technique.
4. **MITRE ATT&CK Coverage** — Deduplicated technique list across the path.
5. **Containment Runbook · staged · pending approval** — Ranked actions
   with exact commands, blast-radius assessment, and rollback notes.
6. **Tool-call trace** — Every tool call the agent made, in order.

---

## The five villa questions

Open `out/report.html` and answer:

### Q1 · Initial access (1 pt)

> Which IP is the attacker operating from, and which two enrichment sources
> independently confirmed it as malicious?

<details><summary>Hint</summary>

Look at the first confirmed node in the **Attack Path** section. The
**evidence ref(s)** counter tells you how many tool calls touched that
node — a `confirmed` IP node has at least two enrichment hits.

</details>

### Q2 · Persistence + privilege escalation (1 pt)

> The attacker created a new permission. What CloudTrail event surfaced
> that change, and to which MITRE technique was it mapped?

<details><summary>Hint</summary>

The **MITRE ATT&CK Coverage** table lists every technique. One of them is
the persistence/privesc class; cross-reference it with the attack-path
node whose phase is `privilege-esc`.

</details>

### Q3 · Collection (1 pt)

> Which AWS service was used to read the customer PII, and what was the
> bucket name?

<details><summary>Hint</summary>

Scroll to the node tagged **T1530 · Data from Cloud Storage**. The
underlying CloudTrail event carries the bucket name in
`requestParameters.bucketName`.

</details>

### Q4 · Exfiltration (2 pts)

> The attacker shared an EBS snapshot externally. What was the snapshot ID,
> and to which external AWS account ID was it shared?

<details><summary>Hint</summary>

Find the **T1537 · Transfer Data to Cloud Account** node. The evidence
section shows the `ModifySnapshotAttribute` event with the snapshot and
the recipient account in `createVolumePermission.add[0].userId`.

</details>

### Q5 · Containment (1 pt — open-ended)

> The toolkit staged five containment actions. List them in priority order
> and state, for each one, the *blast radius* the runbook calls out.

<details><summary>Hint</summary>

The **Containment Runbook** section orders the staged actions. Each card
has explicit *Action / Command / Blast radius / Rollback* fields lifted
from `runbooks/aws/*.yaml`.

</details>

---

## Bonus — bring your own dataset

The villa exercise above uses the dataset that ships with the repo. At the
**Devel Group villa** we'll help you swap in your own:

1. **CloudTrail JSON** — drop your real (or sanitized) events into
   `sample-telemetry/aws/cloudtrail.json` (an array of CloudTrail
   `LookupEvent`-shaped objects — see the sample for the schema).
2. **GuardDuty findings** — `sample-telemetry/aws/guardduty.json`.
3. **VPC flow logs** — `sample-telemetry/aws/vpcflow.json`.
4. **A signal** — write your own Point A in `alerts/`. Minimal shape:

   ```jsonc
   {
     "source": "guardduty",
     "type": "<your finding type>",
     "account_id": "...",
     "region": "...",
     "source_ip": "...",
     "first_seen": "ISO-8601"
   }
   ```

Then re-run:

```bash
ir-agent investigate --signal alerts/your-signal.json --sample
```

You walk out of the villa with **your own** reconstructed-attack-path
report.

---

## Bring your own dockers — add a new enrichment service

The 5 enrichment microservices live in `enrichment-agents/<name>/`. Each is
a tiny FastAPI app + Dockerfile. To add a new provider (e.g. `crowdsec`):

1. `enrichment-agents/crowdsec/{Dockerfile, app.py, requirements.txt}`
2. Append a service entry to `docker-compose.yml`
3. Add a Python client at `ir_agent/tools/enrichment/crowdsec.py`
4. Register the tool in `config/tools.yaml` with
   `phase: enrichment`, `cloud: any`, `enrich_id: crowdsec`

That's it — the orchestrator picks it up on the next run.

---

## Scoring

| Question | Points |
|----------|--------|
| Q1 — Initial access | 1 |
| Q2 — Privilege escalation event + ATT&CK | 1 |
| Q3 — Collection service + bucket | 1 |
| Q4 — Exfil snapshot ID + external account | 2 |
| Q5 — Containment ranking + blast radius | 1 |
| **Total** | **6** |

5/6 or higher gets you a Devel Group sticker and a coffee at the villa.

---

*Hosted by Camilo Fernández · Devel Group · Red Spears Labs · https://www.devel.group*
