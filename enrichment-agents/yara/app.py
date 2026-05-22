"""YARA scan microservice.

Compiles every `*.yar` / `*.yara` file under /app/rules at startup and exposes
a /scan endpoint that accepts base64 file content or a local path.

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

import yara  # type: ignore[import-untyped]
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

RULES_DIR = Path(os.environ.get("YARA_RULES_DIR", "/app/rules"))

app = FastAPI(title="IR enrichment · YARA", version="0.1.0")
log = logging.getLogger("yara")
logging.basicConfig(level=logging.INFO)

RULES: yara.Rules | None = None


@app.on_event("startup")
def _compile_rules() -> None:
    global RULES
    filepaths = {}
    for path in RULES_DIR.rglob("*"):
        if path.suffix.lower() in {".yar", ".yara"} and path.is_file():
            filepaths[path.stem] = str(path)

    if not filepaths:
        log.warning("No YARA rule files found in %s", RULES_DIR)
        RULES = None
        return

    log.info("Compiling %d YARA rule files from %s", len(filepaths), RULES_DIR)
    RULES = yara.compile(filepaths=filepaths)


class ScanRequest(BaseModel):
    content_b64: str | None = None
    path: str | None = None


class Match(BaseModel):
    rule: str
    tags: list[str]
    meta: dict
    strings: list[str]


class ScanResponse(BaseModel):
    matched: bool
    matches: list[Match]


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "rules_loaded": RULES is not None}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    if RULES is None:
        raise HTTPException(503, "YARA rules not compiled — drop rules into /app/rules")

    if req.content_b64:
        data = base64.b64decode(req.content_b64)
        matches = RULES.match(data=data)
    elif req.path:
        p = Path(req.path)
        if not p.is_file():
            raise HTTPException(400, f"Path not found: {req.path}")
        matches = RULES.match(str(p))
    else:
        raise HTTPException(400, "Provide content_b64 or path")

    out_matches = [
        Match(
            rule=m.rule,
            tags=list(m.tags or []),
            meta=dict(m.meta or {}),
            strings=[str(s) for s in (m.strings or [])][:10],
        )
        for m in matches
    ]
    return ScanResponse(matched=bool(out_matches), matches=out_matches)
