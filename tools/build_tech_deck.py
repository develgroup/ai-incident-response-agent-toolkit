"""Build the technical deep-dive slide deck.

Produces `AI-Incident-Response - Technical Deep-Dive.pptx` — a dark-themed
companion deck that mirrors the briefing's 4-layer stack
(TELEMETRY · ENRICHMENT · REASONING · ACTION) and goes deep into each.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Emu, Inches, Pt

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "AI-Incident-Response - Technical Deep-Dive.pptx"

# ─── Devel Group dark palette (mirrors report.html.j2) ───
INK         = RGBColor(0xF5, 0xF5, 0xF1)
PAPER       = RGBColor(0x0D, 0x0F, 0x13)
PANEL       = RGBColor(0x14, 0x17, 0x1D)
LINE        = RGBColor(0x2A, 0x2E, 0x36)
ACCENT      = RGBColor(0xE0, 0x7A, 0x4A)
ACCENT_2    = RGBColor(0xFF, 0xB5, 0x6B)
SOFT        = RGBColor(0x98, 0xA0, 0xAC)
CONFIRMED   = RGBColor(0x5F, 0xD4, 0x7A)
CODE_BG     = RGBColor(0x0A, 0x0B, 0x0E)
CODE_TX     = RGBColor(0xCF, 0xD6, 0xDF)

# Layer colors — TELEMETRY = purple, ENRICHMENT = red, REASONING = purple, ACTION = red.
TELEMETRY_C = RGBColor(0x7A, 0x4F, 0xE0)
ENRICHMENT_C= RGBColor(0xE0, 0x4A, 0x6A)
REASONING_C = RGBColor(0x9B, 0x6B, 0xE0)
ACTION_C    = RGBColor(0xE0, 0x4A, 0x4A)

CODE_FONT   = "Consolas"
SANS        = "Calibri"


def new_deck() -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    return prs


def add_slide(prs: Presentation, *, bg=PAPER):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = bg
    return slide


def add_text(slide, text, left, top, width, height,
             *, size=14, bold=False, color=INK, font=SANS,
             align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(left, top, width, height)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = Emu(0)
    tf.margin_right = Emu(0)
    tf.margin_top = Emu(0)
    tf.margin_bottom = Emu(0)
    first = True
    for line in str(text).split("\n"):
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        p.alignment = align
        first = False
        r = p.add_run()
        r.text = line
        r.font.name = font
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.color.rgb = color
    return tb


def add_code(slide, code, left, top, width, height, *, size=11):
    box = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    box.fill.solid()
    box.fill.fore_color.rgb = CODE_BG
    box.line.color.rgb = LINE
    box.line.width = Pt(0.5)
    box.shadow.inherit = False
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = Emu(91440)
    tf.margin_right = Emu(91440)
    tf.margin_top = Emu(91440)
    tf.margin_bottom = Emu(91440)
    first = True
    for line in code.split("\n"):
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.alignment = PP_ALIGN.LEFT
        r = p.add_run()
        r.text = line if line else " "
        r.font.name = CODE_FONT
        r.font.size = Pt(size)
        r.font.color.rgb = CODE_TX
    return box


def add_header(slide, title, kicker=None, kicker_color=ACCENT):
    if kicker:
        add_text(slide, kicker, Inches(0.6), Inches(0.4),
                 Inches(10), Inches(0.3),
                 size=11, bold=True, color=kicker_color)
    add_text(slide, title, Inches(0.6), Inches(0.65),
             Inches(11.7), Inches(0.8),
             size=26, bold=True, color=INK)
    line = slide.shapes.add_connector(1, Inches(0.6), Inches(1.35),
                                      Inches(12.7), Inches(1.35))
    line.line.color.rgb = kicker_color
    line.line.width = Pt(2)


def add_brand_footer(slide, page=None, total=None):
    add_text(slide,
             "DEVEL GROUP  ·  RED SPEARS LABS",
             Inches(0.6), Inches(7.05), Inches(8), Inches(0.3),
             size=9, bold=True, color=SOFT)
    add_text(slide,
             "www.devel.group  ·  Intelligence-Driven Cybersecurity",
             Inches(0.6), Inches(7.22), Inches(8), Inches(0.3),
             size=9, color=SOFT)
    if page and total:
        add_text(slide, f"{page} / {total}",
                 Inches(12.0), Inches(7.13), Inches(1), Inches(0.3),
                 size=10, color=SOFT, align=PP_ALIGN.RIGHT)


def panel(slide, left, top, width, height, *, accent=ACCENT):
    box = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    box.fill.solid()
    box.fill.fore_color.rgb = PANEL
    box.line.color.rgb = LINE
    box.line.width = Pt(0.5)
    stripe = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top,
                                    Emu(45720), height)
    stripe.fill.solid()
    stripe.fill.fore_color.rgb = accent
    stripe.line.fill.background()
    return box


# ════════════════════════════════════════════════════════════════════
# Slide builders
# ════════════════════════════════════════════════════════════════════

TOTAL = 23


# ── 1. COVER ────────────────────────────────────────────────────────

def slide_cover(prs):
    s = add_slide(prs)
    add_text(s, "DEVEL GROUP  ·  RED SPEARS LABS",
             Inches(0.7), Inches(0.7), Inches(8), Inches(0.4),
             size=11, bold=True, color=ACCENT)
    add_text(s, "AI Incident Response",
             Inches(0.7), Inches(2.4), Inches(12), Inches(1.0),
             size=46, bold=True, color=INK)
    add_text(s, "Technical Deep-Dive",
             Inches(0.7), Inches(3.3), Inches(12), Inches(1.0),
             size=46, bold=True, color=ACCENT_2)
    add_text(s,
             "The full four-layer cycle  ·  telemetry · enrichment · reasoning · action",
             Inches(0.7), Inches(4.4), Inches(12), Inches(0.5),
             size=16, color=SOFT)
    add_text(s, "with Docker composition, code extracts, and end-to-end call flow",
             Inches(0.7), Inches(4.8), Inches(12), Inches(0.5),
             size=14, color=SOFT)
    bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                             Inches(0.7), Inches(5.5),
                             Inches(2.5), Inches(0.06))
    bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background()
    add_text(s, "Camilo Fernández  ·  Devel Group",
             Inches(0.7), Inches(5.7), Inches(8), Inches(0.4),
             size=14, color=INK)
    add_text(s, "Intelligence-Driven Cybersecurity",
             Inches(0.7), Inches(6.05), Inches(8), Inches(0.4),
             size=12, color=SOFT)
    add_text(s, "www.devel.group",
             Inches(0.7), Inches(6.35), Inches(8), Inches(0.4),
             size=12, color=ACCENT_2)
    add_brand_footer(s, 1, TOTAL)


# ── 2. FOUR-LAYER STACK OVERVIEW ────────────────────────────────────

def slide_four_layers(prs):
    s = add_slide(prs)
    add_header(s, "The IR tool stack — four layers an AI responder needs",
               kicker="OVERVIEW")
    layers = [
        ("TELEMETRY",   "What happened — the ground truth",
         "CloudTrail · GuardDuty · VPC Flow · Sentinel KQL · Entra logs · Sysmon · Event Log",
         TELEMETRY_C),
        ("ENRICHMENT",  "Is this entity known-bad?",
         "VirusTotal · AbuseIPDB · Shodan · MalwareBazaar · YARA   (5 Dockerized services)",
         ENRICHMENT_C),
        ("REASONING",   "Correlate, hypothesize, narrate",
         "Claude opus-4-7 + adaptive thinking · validate-and-expand loop · MITRE ATT&CK mapper · attack-graph builder",
         REASONING_C),
        ("ACTION",      "Contain, eradicate, recover  (staged · never executes)",
         "15 runbooks · revoke-key · block-ip-waf · isolate-instance · revoke-snapshot-share · disable-spn · isolate-host · …",
         ACTION_C),
    ]
    top = Inches(1.65)
    rh = Inches(1.32)
    for i, (name, tag, items, color) in enumerate(layers):
        y = top + rh * i
        panel(s, Inches(0.6), y, Inches(12.2), rh - Inches(0.12), accent=color)
        add_text(s, name,
                 Inches(0.9), y + Inches(0.15),
                 Inches(3.0), Inches(0.5),
                 size=22, bold=True, color=color)
        add_text(s, tag,
                 Inches(0.9), y + Inches(0.65),
                 Inches(3.5), Inches(0.4),
                 size=11, color=SOFT)
        add_text(s, items,
                 Inches(4.8), y + Inches(0.25),
                 Inches(7.8), Inches(0.85),
                 size=12, color=INK, font=CODE_FONT)
    add_brand_footer(s, 2, TOTAL)


# ── DIVIDERS for each layer ─────────────────────────────────────────

def layer_divider(prs, label, tagline, color, page):
    s = add_slide(prs)
    # giant left band
    band = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                              Inches(0), Inches(0),
                              Inches(0.5), Inches(7.5))
    band.fill.solid(); band.fill.fore_color.rgb = color
    band.line.fill.background()

    add_text(s, "LAYER",
             Inches(0.9), Inches(2.0), Inches(6), Inches(0.5),
             size=14, bold=True, color=color)
    add_text(s, label,
             Inches(0.9), Inches(2.3), Inches(12), Inches(1.6),
             size=84, bold=True, color=INK)
    add_text(s, tagline,
             Inches(0.9), Inches(4.4), Inches(12), Inches(0.6),
             size=20, color=SOFT)

    bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                             Inches(0.9), Inches(5.2),
                             Inches(2.5), Inches(0.06))
    bar.fill.solid(); bar.fill.fore_color.rgb = color
    bar.line.fill.background()
    add_text(s, "DEVEL GROUP  ·  Intelligence-Driven Cybersecurity",
             Inches(0.9), Inches(5.4), Inches(10), Inches(0.4),
             size=11, color=SOFT)
    add_brand_footer(s, page, TOTAL)


# ── TELEMETRY layer slides ──────────────────────────────────────────

def slide_telemetry_aws(prs):
    s = add_slide(prs)
    add_header(s, "Telemetry · AWS  —  boto3 against the IR-readonly role",
               kicker="TELEMETRY · ir_agent/tools/telemetry/aws_*.py",
               kicker_color=TELEMETRY_C)
    add_text(s,
             "Five tools cover the AWS surface: CloudTrail · GuardDuty · VPC Flow · Config · IAM",
             Inches(0.6), Inches(1.5), Inches(12), Inches(0.4),
             size=13, color=SOFT)
    code = """# ir_agent/tools/telemetry/aws_cloudtrail.py
def lookup(attribute, value, start_time=None, end_time=None, region=None):
    if in_sample_mode():                              # sample dataset shortcut
        events = load_sample("aws", "cloudtrail")
        filtered = [e for e in events if _matches(e, attribute, value)]
        return {"events": filtered[:500], "mode": "sample"}

    client = boto3.client("cloudtrail", region_name=region)
    params = {
        "LookupAttributes": [{"AttributeKey": attribute, "AttributeValue": value}],
        "MaxResults": 50,
    }
    if start_time: params["StartTime"] = _parse_iso(start_time)
    events = []
    for page in client.get_paginator("lookup_events").paginate(**params):
        for ev in page.get("Events", []):
            events.append(_normalize_event(ev))      # → flat dict the model reads
        if len(events) >= 500: break
    return {"events": events[:500], "mode": "live"}"""
    add_code(s, code, Inches(0.6), Inches(2.0), Inches(8.5), Inches(4.0), size=10)
    code2 = """# Valid CloudTrail LookupAttribute keys (enforced by tools.yaml schema)
EventName  ·  Username  ·  EventSource  ·  ResourceName  ·  ResourceType
EventId    ·  AccessKeyId    ·  ReadOnly"""
    add_code(s, code2, Inches(0.6), Inches(6.1), Inches(8.5), Inches(0.85), size=10)

    panel(s, Inches(9.4), Inches(2.0), Inches(3.4), Inches(4.95),
          accent=TELEMETRY_C)
    add_text(s, "Sister tools",
             Inches(9.6), Inches(2.1), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=TELEMETRY_C)
    add_text(
        s,
        "aws.guardduty.findings\n"
        "  → list_findings (severity gte)\n\n"
        "aws.vpcflow.query\n"
        "  → CW Logs Insights query,\n"
        "    polls until Complete\n\n"
        "aws.config.history\n"
        "  → get_resource_config_history\n"
        "    answers \"was it always\n"
        "    this permissive?\"\n\n"
        "aws.iam.get_principal\n"
        "  → resolves AccessKeyId →\n"
        "    user/role + policy set",
        Inches(9.6), Inches(2.55), Inches(3.1), Inches(4.3),
        size=10, color=INK,
    )
    add_brand_footer(s, 4, TOTAL)


def slide_telemetry_azure(prs):
    s = add_slide(prs)
    add_header(s, "Telemetry · Azure  —  Sentinel KQL + Microsoft Graph",
               kicker="TELEMETRY · ir_agent/tools/telemetry/azure_*.py",
               kicker_color=TELEMETRY_C)
    add_text(s,
             "Sign-ins live in FOUR tables — must query all of them to catch SPN / MI activity",
             Inches(0.6), Inches(1.5), Inches(12), Inches(0.4),
             size=13, color=SOFT)
    code = """# Sentinel / Log Analytics — KQL
LogsQueryClient(DefaultAzureCredential()).query_workspace(
    workspace_id=WS,
    query=\"\"\"
        SigninLogs
        | where TimeGenerated > ago(24h)
        | where ResultType == 0 and IPAddress !in (TRUSTED_EGRESS)
        | project TimeGenerated, UserPrincipalName, IPAddress,
                  AuthenticationDetails, MfaDetail, CorrelationId
        | join kind=leftouter (
            AADUserRiskEvents
            | project CorrelationId=RequestId, RiskEventType, RiskLevel
          ) on CorrelationId
    \"\"\",
    timespan=timedelta(hours=24),
)

# Entra ID — Microsoft Graph
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
    ?$filter=createdDateTime gt 2026-05-19T00:00:00Z
    and userPrincipalName eq 'alice@acme.example'
    and ipAddress eq '198.51.100.7'
    &$top=200"""
    add_code(s, code, Inches(0.6), Inches(2.0), Inches(8.5), Inches(4.4), size=10)

    panel(s, Inches(9.4), Inches(2.0), Inches(3.4), Inches(4.4),
          accent=TELEMETRY_C)
    add_text(s, "All four sign-in tables",
             Inches(9.6), Inches(2.1), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=TELEMETRY_C)
    add_text(
        s,
        "SigninLogs\n"
        "  Interactive user sign-ins\n\n"
        "AADNonInteractiveUser\n"
        "  Refresh / OAuth tokens\n\n"
        "AADServicePrincipal\n"
        "  App / SPN auth — the\n"
        "  silent surface\n\n"
        "AADManagedIdentity\n"
        "  System / user-assigned\n"
        "  MI auth\n\n"
        "Plus AuditLogs for directory\n"
        "changes (persistence detection).",
        Inches(9.6), Inches(2.55), Inches(3.1), Inches(3.8),
        size=10, color=INK,
    )
    add_text(s,
             "azure.sentinel.kql  ·  azure.entra.signin_logs  ·  azure.entra.audit_logs  ·  azure.activity.query  ·  azure.graph.activity_logs",
             Inches(0.6), Inches(6.55), Inches(12.2), Inches(0.4),
             size=11, color=ACCENT_2, font=CODE_FONT)
    add_brand_footer(s, 5, TOTAL)


def slide_telemetry_windows(prs):
    s = add_slide(prs)
    add_header(s, "Telemetry · Windows  —  Event Log + Sysmon + tasks",
               kicker="TELEMETRY · ir_agent/tools/telemetry/windows_*.py",
               kicker_color=TELEMETRY_C)
    add_text(s,
             "Sample-mode parses pre-collected JSON. Live mode requires explicit EDR remote-shell authorization — blocked autonomously.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.5),
             size=12, color=SOFT)
    code = """# ir_agent/tools/telemetry/windows_sysmon.py
def query(event_id=None, computer=None, image_contains=None,
          target_image_contains=None, parent_image_contains=None,
          command_line_contains=None, timespan_hours=24):
    if in_sample_mode():
        events = load_sample("windows", "sysmon")
        def _matches(e):
            if event_id and int(e.get("EventID", 0)) != int(event_id):
                return False
            d = e.get("EventData", {})
            if target_image_contains \\
                    and target_image_contains.lower() not in d.get("TargetImage","").lower():
                return False
            return True
        return {"events": [e for e in events if _matches(e)], "mode": "sample"}

    return {"error": "live Sysmon queries require EDR remote-shell authorization",
            "mode": "live-blocked"}"""
    add_code(s, code, Inches(0.6), Inches(2.05), Inches(8.5), Inches(3.5), size=10)

    code2 = """// sample event:
{ "EventID": 10, "Computer": "fin-app-03.acme.local",
  "EventData": {
    "SourceImage": "C:\\\\Windows\\\\Temp\\\\update.exe",
    "TargetImage": "C:\\\\Windows\\\\System32\\\\lsass.exe",
    "GrantedAccess": "0x1010",                       // Mimikatz pattern
    "CallTrace": "ntdll.dll+...|update.exe+..." } }"""
    add_code(s, code2, Inches(0.6), Inches(5.65), Inches(8.5), Inches(1.4), size=9)

    panel(s, Inches(9.4), Inches(2.05), Inches(3.4), Inches(5.0),
          accent=TELEMETRY_C)
    add_text(s, "Four Windows tools",
             Inches(9.6), Inches(2.15), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=TELEMETRY_C)
    add_text(
        s,
        "windows.eventlog.query\n"
        "  Security / TaskScheduler /\n"
        "  WinRM / PowerShell\n"
        "  channels\n\n"
        "windows.sysmon.query\n"
        "  1 ProcessCreate, 3 NetConn,\n"
        "  10 ProcessAccess (LSASS),\n"
        "  11 FileCreate, 13 RegSet\n\n"
        "windows.scheduled_tasks.list\n"
        "  4698 follow-up + author /\n"
        "  action filter\n\n"
        "windows.processes.snapshot\n"
        "  running tree (parent chain)",
        Inches(9.6), Inches(2.55), Inches(3.1), Inches(4.4),
        size=10, color=INK,
    )
    add_brand_footer(s, 6, TOTAL)


def slide_sample_mode(prs):
    s = add_slide(prs)
    add_header(s, "Sample-mode vs live-mode  —  the universal swap",
               kicker="TELEMETRY  ·  the demo path",
               kicker_color=TELEMETRY_C)
    add_text(s,
             "Every telemetry tool honors IR_AGENT_SAMPLE_MODE=1 to read pre-collected JSON instead of calling the live cloud SDK. The demo runs without any cloud credentials.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.6),
             size=12, color=SOFT)
    code = """# ir_agent/tools/telemetry/_sample.py
def in_sample_mode() -> bool:
    return os.environ.get("IR_AGENT_SAMPLE_MODE") == "1"

def load_sample(cloud: str, name: str):
    path = SAMPLE_ROOT / cloud / f"{name}.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


# Every telemetry tool starts the same way:
def lookup(...):
    if in_sample_mode():
        events = load_sample("aws", "cloudtrail")
        return {"events": _filter(events, ...), "mode": "sample"}
    # ... boto3 / MS Graph / Get-WinEvent path ..."""
    add_code(s, code, Inches(0.6), Inches(2.2), Inches(8.5), Inches(4.6), size=11)

    panel(s, Inches(9.4), Inches(2.2), Inches(3.4), Inches(4.6),
          accent=CONFIRMED)
    add_text(s, "sample-telemetry/",
             Inches(9.6), Inches(2.3), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=CONFIRMED)
    add_text(
        s,
        "aws/\n"
        "  cloudtrail.json\n"
        "  guardduty.json\n"
        "  vpcflow.json\n"
        "  iam_principals.json\n"
        "  config.json\n\n"
        "azure/\n"
        "  signinlogs.json\n"
        "  auditlogs.json\n"
        "  activity.json\n"
        "  graph_activity.json\n"
        "  officeactivity.json\n\n"
        "windows/\n"
        "  security_events.json\n"
        "  sysmon.json\n"
        "  scheduled_tasks.json\n"
        "  processes.json",
        Inches(9.6), Inches(2.65), Inches(3.1), Inches(4.1),
        size=10, color=INK, font=CODE_FONT,
    )
    add_brand_footer(s, 7, TOTAL)


# ── ENRICHMENT layer slides ─────────────────────────────────────────

def slide_enrichment_overview(prs):
    s = add_slide(prs)
    add_header(s, "Docker architecture — five services, one bridge network",
               kicker="ENRICHMENT  ·  the only layer that's dockerized",
               kicker_color=ENRICHMENT_C)
    services = [
        ("VirusTotal",    "8081", "/lookup", "hash · url · domain · ip"),
        ("AbuseIPDB",     "8082", "/check",  "ip reputation"),
        ("Shodan",        "8083", "/host",   "ports + banners"),
        ("MalwareBazaar", "8084", "/query",  "sha256 family"),
        ("YARA",          "8085", "/scan",   "local rule scan"),
    ]
    left0 = Inches(0.6)
    top   = Inches(2.0)
    w     = Inches(2.40)
    gap   = Inches(0.10)
    h     = Inches(2.5)
    for i, (name, port, ep, desc) in enumerate(services):
        left = left0 + (w + gap) * i
        panel(s, left, top, w, h, accent=ENRICHMENT_C)
        add_text(s, name, left + Inches(0.15), top + Inches(0.2),
                 w - Inches(0.3), Inches(0.4),
                 size=18, bold=True, color=INK)
        add_text(s, f"port {port}",
                 left + Inches(0.15), top + Inches(0.7),
                 w - Inches(0.3), Inches(0.3),
                 size=10, color=SOFT)
        add_text(s, f"POST {ep}",
                 left + Inches(0.15), top + Inches(1.05),
                 w - Inches(0.3), Inches(0.3),
                 size=12, font=CODE_FONT, color=ACCENT_2)
        add_text(s, desc,
                 left + Inches(0.15), top + Inches(1.55),
                 w - Inches(0.3), Inches(0.8),
                 size=11, color=SOFT)
    add_text(s, "all five containers join the  enrichment  bridge network",
             Inches(0.6), Inches(4.85), Inches(12), Inches(0.4),
             size=13, color=SOFT, align=PP_ALIGN.CENTER)
    add_text(s, "ir-agent  (host process)  →  HTTP  →  localhost:8081-8085",
             Inches(0.6), Inches(5.45), Inches(12), Inches(0.5),
             size=15, bold=True, color=ACCENT_2, align=PP_ALIGN.CENTER,
             font=CODE_FONT)
    add_text(s,
             "Key isolation, per-service rate-limit policy, swappable providers — "
             "the agent never holds a third-party API key in-process.",
             Inches(1.5), Inches(6.1), Inches(10.3), Inches(0.6),
             size=12, color=SOFT, align=PP_ALIGN.CENTER)
    add_brand_footer(s, 9, TOTAL)


def slide_compose_dockerfile(prs):
    s = add_slide(prs)
    add_header(s, "docker-compose.yml + Dockerfile pattern",
               kicker="ENRICHMENT  ·  wired in one file each",
               kicker_color=ENRICHMENT_C)
    code = """services:
  virustotal:
    build: ./enrichment-agents/virustotal
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
    ports: ["8081:8080"]
    networks: [enrichment]

  yara:
    build: ./enrichment-agents/yara
    volumes:
      - ./enrichment-agents/yara/rules:/app/rules:ro
    ports: ["8085:8080"]
    networks: [enrichment]

networks:
  enrichment:
    driver: bridge"""
    add_code(s, code, Inches(0.6), Inches(1.7), Inches(6.0), Inches(4.0), size=11)

    add_text(s, "Every Dockerfile follows the same shape:",
             Inches(7.0), Inches(1.7), Inches(6), Inches(0.4),
             size=12, bold=True, color=SOFT)
    code2 = """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]"""
    add_code(s, code2, Inches(7.0), Inches(2.15), Inches(5.8), Inches(2.2), size=11)

    add_text(s, "YARA adds libssl + libmagic + rules bind-mount:",
             Inches(7.0), Inches(4.5), Inches(6), Inches(0.4),
             size=12, bold=True, color=SOFT)
    code3 = """RUN apt-get install -y libssl-dev libmagic1
COPY rules /app/rules"""
    add_code(s, code3, Inches(7.0), Inches(4.9), Inches(5.8), Inches(0.95), size=11)

    panel(s, Inches(0.6), Inches(5.95), Inches(12.2), Inches(1.0),
          accent=CONFIRMED)
    add_text(s, "Net effect",
             Inches(0.8), Inches(6.05), Inches(11), Inches(0.4),
             size=12, bold=True, color=CONFIRMED)
    add_text(s,
             "Add a new enrichment provider in 4 files (Dockerfile · requirements.txt · app.py · "
             "ir_agent/tools/enrichment/<name>.py). Register one line in tools.yaml.",
             Inches(0.8), Inches(6.42), Inches(11.8), Inches(0.6),
             size=11, color=INK)
    add_brand_footer(s, 10, TOTAL)


def slide_fastapi_pattern(prs):
    s = add_slide(prs)
    add_header(s, "FastAPI service pattern — Pydantic + httpx + /health",
               kicker="ENRICHMENT  ·  every app.py looks like this",
               kicker_color=ENRICHMENT_C)
    code = """import os, httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
app = FastAPI(title="IR enrichment · VirusTotal", version="0.1.0")

class LookupRequest(BaseModel):
    indicator: str
    kind: Literal["hash", "url", "domain", "ip"]

class LookupResponse(BaseModel):
    indicator: str
    kind: str
    malicious: bool
    detections: int
    total_engines: int
    families: list[str]
    raw_attributes: dict

@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "configured": bool(VT_API_KEY)}

@app.post("/lookup", response_model=LookupResponse)
async def lookup(req: LookupRequest) -> LookupResponse:
    if not VT_API_KEY:
        raise HTTPException(503, "VIRUSTOTAL_API_KEY not configured")
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"{VT_BASE}/{_path_for(req.kind, req.indicator)}",
                                headers={"x-apikey": VT_API_KEY})
    # ... normalize provider response → flat shape the agent reads ..."""
    add_code(s, code, Inches(0.6), Inches(1.7), Inches(12.2), Inches(5.3), size=10)
    add_brand_footer(s, 11, TOTAL)


def slide_api_contracts(prs):
    s = add_slide(prs)
    add_header(s, "API contracts — the five enrichment endpoints",
               kicker="ENRICHMENT  ·  HTTP · JSON",
               kicker_color=ENRICHMENT_C)
    rows = [
        ("VirusTotal",    "POST /lookup",
         '{ "indicator": "198.51.100.7", "kind": "ip" }',
         '{ "malicious": false, "detections": 0, "total_engines": 91, '
         '"families": [], "raw_attributes": {...} }'),
        ("AbuseIPDB",     "POST /check",
         '{ "ip": "198.51.100.7", "max_age_in_days": 90 }',
         '{ "malicious": true, "abuse_confidence_score": 96, "total_reports": 120, '
         '"country_code": "US", "is_tor": false }'),
        ("Shodan",        "POST /host",
         '{ "ip": "198.51.100.7" }',
         '{ "suspicious": true, "ports": [22, 9001], "tags": ["tor","proxy"], '
         '"org": "Tor-exit", "os": null }'),
        ("MalwareBazaar", "POST /query",
         '{ "sha256": "AA112233..." }',
         '{ "malicious": true, "signature": "Cobalt Strike", "file_type": "exe", '
         '"tags": ["beacon"], "related_samples": 12 }'),
        ("YARA",          "POST /scan",
         '{ "content_b64": "<base64>" }   or  { "path": "..." }',
         '{ "matched": true, "matches": [ { "rule": "...", "tags": [...], '
         '"meta": {...}, "strings": [...] } ] }'),
    ]
    top = Inches(1.8)
    rh  = Inches(1.02)
    for i, (name, ep, req, resp) in enumerate(rows):
        y = top + rh * i
        panel(s, Inches(0.6), y, Inches(12.2), rh - Inches(0.08),
              accent=ENRICHMENT_C)
        add_text(s, name, Inches(0.8), y + Inches(0.1),
                 Inches(1.8), Inches(0.3),
                 size=13, bold=True, color=ACCENT_2)
        add_text(s, ep, Inches(0.8), y + Inches(0.42),
                 Inches(1.8), Inches(0.3),
                 size=11, color=SOFT, font=CODE_FONT)
        add_text(s, "req  " + req,
                 Inches(2.6), y + Inches(0.06),
                 Inches(10.1), Inches(0.35),
                 size=10, color=INK, font=CODE_FONT)
        add_text(s, "resp " + resp,
                 Inches(2.6), y + Inches(0.45),
                 Inches(10.1), Inches(0.5),
                 size=10, color=CONFIRMED, font=CODE_FONT)
    add_brand_footer(s, 12, TOTAL)


def slide_env_and_yara(prs):
    s = add_slide(prs)
    add_header(s, "Environment flow + YARA hot-reload",
               kicker="ENRICHMENT  ·  secrets stay in containers",
               kicker_color=ENRICHMENT_C)

    add_text(s, ".env → docker-compose → container env → app.py",
             Inches(0.6), Inches(1.55), Inches(12), Inches(0.4),
             size=14, color=ACCENT_2, font=CODE_FONT)
    stages = [
        (".env",
         "VIRUSTOTAL_API_KEY=fde6...\nABUSEIPDB_API_KEY=...\nSHODAN_API_KEY=..."),
        ("docker-compose.yml",
         "environment:\n  - VIRUSTOTAL_API_KEY=\n    ${VIRUSTOTAL_API_KEY}"),
        ("container env",
         "$ docker exec ...\n  env | grep VT\nVIRUSTOTAL_API_KEY=fde6..."),
        ("app.py",
         "key = os.environ.get(\n  \"VIRUSTOTAL_API_KEY\", \"\")\nif not key:\n  raise HTTPException(503)"),
    ]
    left0 = Inches(0.6)
    w     = Inches(2.9)
    gap   = Inches(0.30)
    top   = Inches(2.05)
    h     = Inches(2.4)
    for i, (title, body) in enumerate(stages):
        left = left0 + (w + gap) * i
        panel(s, left, top, w, h, accent=ENRICHMENT_C)
        add_text(s, title, left + Inches(0.15), top + Inches(0.15),
                 w - Inches(0.3), Inches(0.4),
                 size=13, bold=True, color=ACCENT_2)
        add_code(s, body, left + Inches(0.15), top + Inches(0.6),
                 w - Inches(0.3), h - Inches(0.75), size=10)
    for i in range(3):
        arrow_x = left0 + (w + gap) * (i + 1) - gap + Emu(45720)
        ar = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                arrow_x - Emu(180000),
                                top + h / 2 - Emu(120000),
                                Emu(220000), Emu(240000))
        ar.fill.solid(); ar.fill.fore_color.rgb = ENRICHMENT_C
        ar.line.fill.background()

    panel(s, Inches(0.6), Inches(4.7), Inches(12.2), Inches(2.25),
          accent=CONFIRMED)
    add_text(s, "YARA · hot-reload from the host",
             Inches(0.8), Inches(4.8), Inches(11), Inches(0.4),
             size=13, bold=True, color=CONFIRMED)
    code = """volumes:
  - ./enrichment-agents/yara/rules:/app/rules:ro    # bind-mount, read-only

# Update a rule on the host, then:
$ docker compose restart yara                       # picks up the new rules
$ curl http://localhost:8085/health
  {"status": "ok", "rules_loaded": true}"""
    add_code(s, code, Inches(0.8), Inches(5.2), Inches(11.7), Inches(1.65), size=10)
    add_brand_footer(s, 13, TOTAL)


# ── REASONING layer slides ──────────────────────────────────────────

def slide_operating_contract(prs):
    s = add_slide(prs)
    add_header(s, "The operating contract — five non-negotiables",
               kicker="REASONING  ·  agents/ir-agent.system.md",
               kicker_color=REASONING_C)
    add_text(s,
             "Every investigation follows this contract. The model is forbidden from relaxing it.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.5),
             size=13, color=SOFT)
    rules = [
        ("1.  Start at Point A",
         "One alert, one anomaly. Never a blank page. Everything else is unknown until cited."),
        ("2.  Two-source rule",
         "No claim becomes a confirmed node until corroborated by TWO independent sources. "
         "Otherwise it stays a hypothesis."),
        ("3.  Cite everything",
         "Every node and every edge references its log line, event ID, or tool response. "
         "A claim without a citation does not exist."),
        ("4.  MITRE ATT&CK-mapped",
         "Every confirmed node is tagged with a technique ID + name from "
         "config/mitre-attack-map.yaml."),
        ("5.  Stage, never execute",
         "Humans own irreversible actions. The agent stages containment; it never runs "
         "destructive changes without out-of-band approval."),
    ]
    top = Inches(2.1)
    rh = Inches(0.95)
    for i, (head, body) in enumerate(rules):
        y = top + rh * i
        panel(s, Inches(0.6), y, Inches(12.2), rh - Inches(0.1),
              accent=REASONING_C)
        add_text(s, head, Inches(0.85), y + Inches(0.1),
                 Inches(3.6), Inches(0.4),
                 size=14, bold=True, color=ACCENT_2)
        add_text(s, body, Inches(4.5), y + Inches(0.12),
                 Inches(8.0), Inches(0.7),
                 size=12, color=INK)
    add_brand_footer(s, 15, TOTAL)


def slide_llm_loop(prs):
    s = add_slide(prs)
    add_header(s, "The tool-use loop — Anthropic SDK + manual orchestration",
               kicker="REASONING  ·  ir_agent/orchestrator.py",
               kicker_color=REASONING_C)
    code = """response = client.messages.create(
    model="claude-opus-4-7",                          # latest Opus
    max_tokens=16000,
    system=[{
        "type": "text",
        "text": system_prompt,                        # ~30 KB master + specialist + tenant
        "cache_control": {"type": "ephemeral"},       # ~90% cache hit after first call
    }],
    tools=anthropic_tools,                            # built from config/tools.yaml
    thinking={"type": "adaptive"},                    # model decides depth
    output_config={"effort": "high"},
    messages=messages,
)

if response.stop_reason == "end_turn":
    break

for block in response.content:
    if block.type == "tool_use":
        spec = tool_by_anthropic_name(specs, block.name)
        result = spec.callable(**dict(block.input))   # dispatches to enrichment /
                                                      # telemetry / action handler

        if spec.destructive:
            staged_actions.append(StagedAction(       # ← approval-gated track
                tool_id=spec.id, parameters=dict(block.input), result=result,
            ))
        tool_results.append({"type": "tool_result", "tool_use_id": block.id,
                             "content": json.dumps(result, default=str)})"""
    add_code(s, code, Inches(0.6), Inches(1.7), Inches(8.5), Inches(5.4), size=10)

    panel(s, Inches(9.4), Inches(1.7), Inches(3.4), Inches(5.4),
          accent=REASONING_C)
    add_text(s, "Why a manual loop",
             Inches(9.6), Inches(1.8), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=ACCENT_2)
    add_text(
        s,
        "The Anthropic SDK tool\n"
        "runner is faster to write but\n"
        "doesn't expose a hook to\n"
        "intercept tool calls.\n\n"
        "We need to split destructive\n"
        "vs read-only calls — every\n"
        "stage_* action is recorded\n"
        "as a separate StagedAction\n"
        "so the report can render an\n"
        "approval gate per item.\n\n"
        "Prompt caching trims ~90% of\n"
        "token cost on multi-turn\n"
        "investigations.",
        Inches(9.6), Inches(2.25), Inches(3.1), Inches(4.8),
        size=10, color=INK,
    )
    add_brand_footer(s, 16, TOTAL)


def slide_graph_mitre(prs):
    s = add_slide(prs)
    add_header(s, "Attack-graph builder + MITRE ATT&CK mapper",
               kicker="REASONING  ·  ir_agent/graph/",
               kicker_color=REASONING_C)
    add_text(s,
             "The tool-call trace becomes a directed graph. Each confirmed node carries an ATT&CK technique looked up from the YAML map.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.6),
             size=12, color=SOFT)
    code = """# config/mitre-attack-map.yaml  (excerpt)
aws:
  ModifySnapshotAttribute: { id: T1537, name: "Transfer Data to Cloud Account",
                             phase: exfiltration }
  PutUserPolicy:           { id: T1098.003, name: "Additional Cloud Roles",
                             phase: privilege-esc }
windows:
  "4624":     { id: T1078,     name: "Valid Accounts",       phase: credential-use }
  "1102":     { id: T1070.001, name: "Clear Event Logs",     phase: defense-evasion }
  "sysmon-10":{ id: T1003.001, name: "OS Credential Dumping: LSASS Memory",
                phase: credential-access }

# ir_agent/graph/builder.py — promote nodes when techniques apply
def _node_for_event(cloud, ev, attack):
    event_name = ev.get("eventName") or ev.get("operationName")
    if not event_name and (eid := ev.get("EventID")) is not None:
        channel = (ev.get("Channel") or "").lower()
        key = f"sysmon-{eid}" if "sysmon" in channel else str(eid)
        attack = map_event(cloud, key)
    return AttackNode(..., attack_technique=attack["id"] if attack else None)"""
    add_code(s, code, Inches(0.6), Inches(2.15), Inches(12.2), Inches(4.7), size=10)
    add_brand_footer(s, 17, TOTAL)


# ── ACTION layer slides ─────────────────────────────────────────────

def slide_action_design(prs):
    s = add_slide(prs)
    add_header(s, "Staged containment — the approval gate",
               kicker="ACTION  ·  the rule that does not change",
               kicker_color=ACTION_C)
    add_text(s,
             "Containment tools NEVER call boto3 / Graph / Get-WinEvent. They render a runbook YAML with parameters and return a proposed-action object.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.6),
             size=13, color=SOFT)
    code = """# ir_agent/tools/action/_runbook.py
def stage(cloud, runbook, params):
    path = RUNBOOK_ROOT / cloud / f"{runbook}.yaml"
    raw  = path.read_text(encoding="utf-8")
    rendered = Template(raw).safe_substitute({k: str(v) for k, v in params.items()})
    spec = yaml.safe_load(rendered)
    return {
        "approval_required": True,                    # ← non-negotiable
        "staged_at":  datetime.now(timezone.utc).isoformat(),
        "runbook":    runbook,
        "cloud":      cloud,
        "phase":      spec.get("phase", "contain"),
        "action":     spec.get("action"),
        "command":    spec.get("command"),
        "blast_radius": spec.get("blast_radius"),
        "rollback":   spec.get("rollback"),
        "rationale":  params.get("rationale", ""),
        "parameters": params,
    }
# Note: this function NEVER calls subprocess, boto3, or any cloud SDK."""
    add_code(s, code, Inches(0.6), Inches(2.2), Inches(8.5), Inches(4.7), size=10)

    panel(s, Inches(9.4), Inches(2.2), Inches(3.4), Inches(4.7),
          accent=ACTION_C)
    add_text(s, "What this guarantees",
             Inches(9.6), Inches(2.3), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=ACCENT_2)
    add_text(
        s,
        "Even if the LLM goes rogue:\n\n"
        "• No process spawn\n"
        "• No outbound API call\n"
        "• No state change\n\n"
        "The agent surface for the\n"
        "destructive layer is only\n"
        "ever a YAML renderer.\n\n"
        "The actual execution\n"
        "lives outside the agent —\n"
        "in the responder's own\n"
        "approval workflow.",
        Inches(9.6), Inches(2.65), Inches(3.1), Inches(4.1),
        size=10, color=INK,
    )
    add_brand_footer(s, 19, TOTAL)


def slide_runbook_library(prs):
    s = add_slide(prs)
    add_header(s, "The runbook library — 15 staged actions across 3 platforms",
               kicker="ACTION  ·  runbooks/",
               kicker_color=ACTION_C)
    add_text(s,
             "Every YAML carries: action · command · blast_radius · rollback. The agent never reads command in isolation.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.5),
             size=12, color=SOFT)

    cols = [
        ("AWS  (5)", ACTION_C, [
            "revoke-access-key       contain",
            "block-ip-waf            contain",
            "isolate-instance        contain",
            "rescope-role            eradicate",
            "revoke-snapshot-share   eradicate",
        ]),
        ("Azure  (5)", ACTION_C, [
            "revoke-sessions             contain",
            "conditional-access-block    contain",
            "remove-app-credential       contain",
            "disable-spn                 eradicate",
            "revoke-storage-sas          eradicate",
        ]),
        ("Windows  (5)", ACTION_C, [
            "isolate-host          contain",
            "kill-process          contain",
            "disable-account       contain",
            "remove-scheduled-task eradicate",
            "stop-disable-service  eradicate",
        ]),
    ]
    left0 = Inches(0.6)
    w     = Inches(4.0)
    gap   = Inches(0.15)
    top   = Inches(2.15)
    h     = Inches(3.2)
    for i, (head, accent, items) in enumerate(cols):
        left = left0 + (w + gap) * i
        panel(s, left, top, w, h, accent=accent)
        add_text(s, head, left + Inches(0.2), top + Inches(0.15),
                 w - Inches(0.4), Inches(0.4),
                 size=15, bold=True, color=ACCENT_2)
        for j, item in enumerate(items):
            add_text(s, "• " + item,
                     left + Inches(0.2), top + Inches(0.6) + Inches(0.45) * j,
                     w - Inches(0.4), Inches(0.4),
                     size=11, color=INK, font=CODE_FONT)

    panel(s, Inches(0.6), Inches(5.55), Inches(12.2), Inches(1.45),
          accent=CONFIRMED)
    add_text(s, "Runbook YAML — every file has the same shape",
             Inches(0.8), Inches(5.6), Inches(11), Inches(0.4),
             size=12, bold=True, color=CONFIRMED)
    code = """action: |  Mark the IAM access key as Inactive…
command: |  aws iam update-access-key --access-key-id ${access_key_id} --status Inactive
blast_radius: |  All processes using this key get InvalidClientTokenId within minutes.
rollback: |  aws iam update-access-key --access-key-id ${access_key_id} --status Active"""
    add_code(s, code, Inches(0.8), Inches(5.95), Inches(11.8), Inches(1.0), size=10)
    add_brand_footer(s, 20, TOTAL)


def slide_tools_registry(prs):
    s = add_slide(prs)
    add_header(s, "tools.yaml — the single source of truth",
               kicker="ACTION  ·  the contract the LLM reads",
               kicker_color=ACTION_C)
    add_text(s,
             "Every tool entry maps directly to a Python function. Adding a tool = (1) write the function, (2) one entry here.",
             Inches(0.6), Inches(1.5), Inches(12.2), Inches(0.5),
             size=12, color=SOFT)
    code = """- id: aws.iam.stage_disable_key
  phase: action
  cloud: aws
  destructive: true                                   # ← triggers the approval gate
  description: |
    STAGE an IAM access key deactivation. Returns the boto3 command and
    blast radius. Does NOT execute. Use for compromised access keys.
  handler: ir_agent.tools.action.aws_stage.disable_access_key
  input_schema:
    type: object
    properties:
      access_key_id: { type: string }
      username:      { type: string }
      rationale:     { type: string }
    required: [access_key_id, rationale]"""
    add_code(s, code, Inches(0.6), Inches(2.1), Inches(8.5), Inches(3.7), size=11)

    code2 = """# At investigation start:
specs = load_tools(cloud="aws", enrich=["virustotal"])    # → 11 tools
anthropic_tools = [s.to_anthropic_tool() for s in specs]  # → JSON schemas

# Filters available via CLI flags:
#   --cloud {aws|azure|gcp|windows}      filters by platform
#   --enrich vt,ai,sh,mb,yara | all | none   filters enrichment subset"""
    add_code(s, code2, Inches(0.6), Inches(5.9), Inches(8.5), Inches(1.2), size=10)

    panel(s, Inches(9.4), Inches(2.1), Inches(3.4), Inches(5.0),
          accent=ACTION_C)
    add_text(s, "25 tools registered",
             Inches(9.6), Inches(2.2), Inches(3.1), Inches(0.4),
             size=13, bold=True, color=ACCENT_2)
    add_text(
        s,
        "5  enrichment  (any cloud)\n\n"
        "5  AWS telemetry\n"
        "5  Azure telemetry\n"
        "4  Windows telemetry\n\n"
        "5  AWS action\n"
        "5  Azure action\n"
        "5  Windows action\n\n"
        "Total surface available to\n"
        "the model in a single tool-\n"
        "use loop — filtered by\n"
        "--cloud / --enrich at\n"
        "investigation start.",
        Inches(9.6), Inches(2.65), Inches(3.1), Inches(4.4),
        size=10, color=INK,
    )
    add_brand_footer(s, 21, TOTAL)


# ── End-to-end + Quickstart ─────────────────────────────────────────

def slide_end_to_end(prs):
    s = add_slide(prs)
    add_header(s, "End-to-end  —  one Point A traversing the four layers",
               kicker="THE FULL CYCLE")
    code = """┌──────────────────┐        Point A:  GuardDuty finding · IAM key seen from 198.51.100.7
│  Point A signal  │
└────────┬─────────┘
         │
         ▼   ① ENRICH       abuseipdb.check(198.51.100.7) → 96/100 malicious
   ┌─────────────────┐      shodan.host(198.51.100.7)     → tags=[tor, proxy]
   │   ENRICHMENT    │      virustotal.lookup(...)        → second-source confirmation
   └────────┬────────┘
            │
            ▼   ② OBSERVE   aws.cloudtrail.lookup(AccessKeyId, AKIA…)  →  5 events
   ┌─────────────────┐      aws.iam.get_principal(AKIA…) →  role/web-prod-ec2
   │    TELEMETRY    │      aws.config.history(...)      →  policy widened 2026-05-18
   └────────┬────────┘      aws.vpcflow.query(dst=198.51.100.7) → 1 egress flow
            │
            ▼   ③ REASON    validate-and-expand loop  ·  two-source confirmation
   ┌─────────────────┐      attack-graph: 5 nodes  ·  MITRE: T1098.003 / T1530 / T1537
   │    REASONING    │      narrative: leaked-key  →  S3 read  →  privesc  →  snapshot
   └────────┬────────┘                              →  ModifySnapshotAttribute (exfil)
            │
            ▼   ④ STAGE      aws.iam.stage_disable_key(AKIA…)
   ┌─────────────────┐       aws.network.stage_waf_block(198.51.100.7/32)
   │     ACTION      │       aws.iam.stage_rescope_role(web-prod-ec2)
   └────────┬────────┘       aws.ec2.stage_revoke_snapshot_share(snap-…, 999988887777)
            │                aws.ec2.stage_isolate_instance(i-…, sg-quarantine)
            ▼
   ┌─────────────────┐
   │   report.html   │   ←  attack graph · MITRE coverage · ranked staged runbook
   └─────────────────┘"""
    add_code(s, code, Inches(0.4), Inches(1.55), Inches(12.6), Inches(5.4), size=9)
    add_brand_footer(s, 22, TOTAL)


def slide_quickstart(prs):
    s = add_slide(prs)
    add_header(s, "Quickstart — three commands", kicker="GET RUNNING")
    add_text(s, "Clone, bring up the enrichment dockers, install the CLI, run a reconstruction.",
             Inches(0.6), Inches(1.5), Inches(12), Inches(0.4),
             size=13, color=SOFT)
    code = """$ git clone github.com/devel-group/ai-incident-response
$ cd ai-incident-response
$ cp .env.example .env      # ANTHROPIC_API_KEY + optional VT/AbuseIPDB/Shodan keys

$ docker compose up -d enrichment-agents
  Container ir-enrichment-virustotal    Started
  Container ir-enrichment-abuseipdb     Started
  Container ir-enrichment-shodan        Started
  Container ir-enrichment-malwarebazaar Started
  Container ir-enrichment-yara          Started

$ pip install -e .

$ ir-agent investigate --signal alerts/aws-guardduty-cred-exfil.json --sample
  validating... expanding... mapping ATT&CK... (cloud=AWS · enrich=all)
  iter=1 stop_reason=tool_use   cache_read=0
  iter=2 stop_reason=tool_use   cache_read=5821
  ...
  iter=8 stop_reason=end_turn   cache_read=11823
  reconstruction complete · 8 iterations
  Attack path reconstructed → out/report.html
  Machine-readable graph →    out/report.json
  5 containment actions staged pending human approval."""
    add_code(s, code, Inches(0.6), Inches(2.0), Inches(12.2), Inches(4.9), size=11)
    add_brand_footer(s, 23, TOTAL)


# ════════════════════════════════════════════════════════════════════
# Build
# ════════════════════════════════════════════════════════════════════

def main() -> None:
    prs = new_deck()
    # 1
    slide_cover(prs)
    # 2
    slide_four_layers(prs)
    # 3  -- divider --
    layer_divider(prs, "TELEMETRY",
                  "What happened — the ground truth", TELEMETRY_C, 3)
    # 4 / 5 / 6 / 7
    slide_telemetry_aws(prs)
    slide_telemetry_azure(prs)
    slide_telemetry_windows(prs)
    slide_sample_mode(prs)
    # 8  -- divider --
    layer_divider(prs, "ENRICHMENT",
                  "Is this entity known-bad?", ENRICHMENT_C, 8)
    # 9 / 10 / 11 / 12 / 13
    slide_enrichment_overview(prs)
    slide_compose_dockerfile(prs)
    slide_fastapi_pattern(prs)
    slide_api_contracts(prs)
    slide_env_and_yara(prs)
    # 14 -- divider --
    layer_divider(prs, "REASONING",
                  "Correlate, hypothesize, narrate", REASONING_C, 14)
    # 15 / 16 / 17
    slide_operating_contract(prs)
    slide_llm_loop(prs)
    slide_graph_mitre(prs)
    # 18 -- divider --
    layer_divider(prs, "ACTION",
                  "Contain, eradicate, recover  (staged · never executes)",
                  ACTION_C, 18)
    # 19 / 20 / 21
    slide_action_design(prs)
    slide_runbook_library(prs)
    slide_tools_registry(prs)
    # 22 / 23
    slide_end_to_end(prs)
    slide_quickstart(prs)

    prs.save(str(OUT_PATH))
    print(f"OK wrote {OUT_PATH}  ·  {OUT_PATH.stat().st_size:,} bytes  ·  {len(prs.slides)} slides")


if __name__ == "__main__":
    main()
