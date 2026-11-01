#!/usr/bin/env python3
"""SSDLC gate scanner: secrets and dangerous code patterns.

Standard library only, no network. Usage:
    python3 -I gate_scan.py [--json] PATH [PATH ...]
Exit status: 0 no findings, 1 findings, 2 usage error.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass

MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
ALLOW_MARK = "ssdlc: allow"

# (rule, severity, regex). Secrets first.
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("secret.aws-access-key", "critical", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret.github-token", "critical", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("secret.anthropic-key", "critical", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("secret.openai-key", "critical", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
    ("secret.slack-token", "critical", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("secret.private-key", "critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("secret.hardcoded-credential", "high", re.compile(
        r"""(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\b\s*[:=]\s*["'][^"'\s]{8,}["']""")),
    ("code.shell-injection", "high", re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.system\(|\bos\.popen\(")),
    ("code.eval", "high", re.compile(r"(?<![\w.])(eval|exec)\s*\(|new\s+Function\s*\(")),
    ("code.unsafe-deserialization", "high", re.compile(
        r"\bpickle\.loads?\(|\bmarshal\.loads?\(|\byaml\.load\((?![^)]*Loader\s*=\s*yaml\.(Safe|CSafe)Loader)")),
    ("code.sql-string-build", "high", re.compile(
        r"""(?i)\.execute\(\s*(f["']|["'][^"']*\b(select|insert|update|delete)\b[^"']*["']\s*(%|\+|\.format))""")),
    ("code.tls-verify-disabled", "medium", re.compile(
        r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0")),
    ("code.weak-hash", "medium", re.compile(r"\bhashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]")),
    ("code.insecure-random-token", "low", re.compile(r"(?i)(token|secret|nonce|password)\w*\s*=\s*.*\brandom\.(random|randint|choice)\(")),
]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    excerpt: str


def redact(text: str) -> str:
    """Show at most the first 4 chars of each long token in a secret match."""
    def cut(m: re.Match[str]) -> str:
        s = m.group(0)
        return s[:4] + "…" if len(s) > 8 else s
    return re.sub(r"[A-Za-z0-9_\-/+]{9,}", cut, text)


def excerpt(line: str, rule: str, m: re.Match[str]) -> str:
    """Code findings keep their evidence verbatim; secret findings hide the value."""
    if rule.startswith("secret."):
        line = line[: m.start()] + redact(m.group(0)) + line[m.end():]
    return line.strip()[:160]


def scan_text(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for rule, sev, rx in RULES:
            m = rx.search(line)
            if m:
                out.append(Finding(rule, sev, path, n, excerpt(line, rule, m)))
    return out


def iter_files(paths: list[str]):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in sorted(files):
                    yield os.path.join(root, f)
        elif os.path.isfile(p):
            yield p


def scan_paths(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for f in iter_files(paths):
        try:
            if os.path.getsize(f) > MAX_BYTES:
                continue
            with open(f, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            continue  # binary
        findings.extend(scan_text(data.decode("utf-8", "replace"), f))
    return findings


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if a != "--json"]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    findings = scan_paths(paths)
    if as_json:
        print(json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))
    else:
        for f in findings:
            print(f"{f.severity.upper():8} {f.rule:32} {f.file}:{f.line}  {f.excerpt}")
        print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
