"""Build a clean release ZIP suitable for uploading to GitHub.

Excludes anything sensitive or auto-generated:
  .env  (has API keys — never ship)
  out/             (generated reports)
  __pycache__/     (anywhere)
  *.pyc / *.pyo
  .pytest_cache, .mypy_cache, .ruff_cache, .venv, venv
  *.egg-info
  _pptx_extract, _final_extract (my temp dirs)
  .DS_Store, Thumbs.db
  *.log
  the zip itself

DEVEL GROUP · Red Spears Labs · https://www.devel.group · Apache-2.0
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TODAY = _dt.date.today().isoformat()
RELEASE_DIR_NAME = "ai-incident-response"
OUT_ZIP = REPO_ROOT.parent / f"ai-incident-response-{TODAY}.zip"

# Files/dirs/patterns to exclude. Globs match against the path relative to REPO_ROOT.
EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "out", "_pptx_extract", "_final_extract",
    ".git",  # in case someone runs this inside a checked-out clone
    "node_modules",
}
EXCLUDE_FILES = {
    ".env", ".DS_Store", "Thumbs.db",
}
EXCLUDE_PATTERNS = [
    "*.pyc", "*.pyo", "*.log", "*.egg-info", "*.egg-info/*",
    "ai-incident-response-*.zip",
]


def _excluded(rel: Path) -> bool:
    parts = set(rel.parts)
    if parts & EXCLUDE_DIRS:
        return True
    if rel.name in EXCLUDE_FILES:
        return True
    for pat in EXCLUDE_PATTERNS:
        if fnmatch.fnmatch(rel.as_posix(), pat) or fnmatch.fnmatch(rel.name, pat):
            return True
    return False


def main() -> None:
    files: list[tuple[Path, str]] = []
    for p in sorted(REPO_ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO_ROOT)
        if _excluded(rel):
            continue
        # Skip the zip if a previous run left one in repo root (shouldn't, but safe).
        if rel.suffix == ".zip" and rel.name.startswith("ai-incident-response-"):
            continue
        arcname = f"{RELEASE_DIR_NAME}/{rel.as_posix()}"
        files.append((p, arcname))

    OUT_ZIP.unlink(missing_ok=True)
    with zipfile.ZipFile(OUT_ZIP, "w",
                         compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as zf:
        for src, arcname in files:
            zf.write(src, arcname=arcname)

    size = OUT_ZIP.stat().st_size
    print(f"OK wrote {OUT_ZIP}")
    print(f"   {len(files):>4} files")
    print(f"   {size:>9,} bytes  ({size/1024/1024:.2f} MiB)")
    print()
    print("Sample of included files (first 30):")
    for _, arcname in files[:30]:
        print(f"   {arcname}")
    if len(files) > 30:
        print(f"   ... + {len(files) - 30} more")


if __name__ == "__main__":
    main()
