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

# (rule, severity, refs, regex). refs: CWE ids and OWASP 2026 ids
# (LLMnn:2026 = LLM Top 10 2026, ASInn = Agentic Top 10 2026). Secrets first.
RULES: list[tuple[str, str, list[str], re.Pattern[str]]] = [
    ("secret.aws-access-key", "critical", ["CWE-798"], re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret.github-token", "critical", ["CWE-798"], re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("secret.anthropic-key", "critical", ["CWE-798", "LLM02:2026"], re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("secret.openai-key", "critical", ["CWE-798", "LLM02:2026"], re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
    ("secret.slack-token", "critical", ["CWE-798"], re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("secret.private-key", "critical", ["CWE-321"], re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("secret.hardcoded-credential", "high", ["CWE-798"], re.compile(
        r"""(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\b\s*[:=]\s*["'][^"'\s]{8,}["']""")),
    ("code.shell-injection", "high", ["CWE-78"], re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.system\(|\bos\.popen\(")),
    ("code.eval", "high", ["CWE-95"], re.compile(r"(?<![\w.])(eval|exec)\s*\(|new\s+Function\s*\(")),
    ("code.unsafe-deserialization", "high", ["CWE-502"], re.compile(
        r"\bpickle\.loads?\(|\bmarshal\.loads?\(|\byaml\.load\((?![^)]*Loader\s*=\s*yaml\.(Safe|CSafe)Loader)")),
    ("code.sql-string-build", "high", ["CWE-89"], re.compile(
        r"""(?i)\.execute\(\s*(f["']|["'][^"']*\b(select|insert|update|delete)\b[^"']*["']\s*(%|\+|\.format))""")),
    ("code.tls-verify-disabled", "medium", ["CWE-295"], re.compile(
        r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0")),
    ("code.weak-hash", "medium", ["CWE-328"], re.compile(r"\bhashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]")),
    ("code.insecure-random-token", "low", ["CWE-338"], re.compile(r"(?i)(token|secret|nonce|password)\w*\s*=\s*.*\brandom\.(random|randint|choice)\(")),
]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    excerpt: str
    refs: list[str]


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
        for rule, sev, refs, rx in RULES:
            m = rx.search(line)
            if m:
                out.append(Finding(rule, sev, path, n, excerpt(line, rule, m), list(refs)))
    return out


def iter_files(paths: list[str]):
    """Yield (path, link_target) for regular files; symlinks are never followed.

    link_target is set when the entry is a symlink, so the caller can report it
    without reading through it (a planted link to ~/.ssh/id_rsa must not leak).
    """
    for p in paths:
        if os.path.islink(p):
            yield p, os.readlink(p)
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):  # followlinks=False by default
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for d in dirs:
                    full = os.path.join(root, d)
                    if os.path.islink(full):
                        yield full, os.readlink(full)
                for f in sorted(files):
                    full = os.path.join(root, f)
                    yield full, (os.readlink(full) if os.path.islink(full) else None)
        elif os.path.isfile(p):
            yield p, None


def link_escapes(link: str, target: str, roots: list[str]) -> bool:
    resolved = os.path.realpath(os.path.join(os.path.dirname(link), target))
    bases = [os.path.realpath(r if os.path.isdir(r) else os.path.dirname(r) or ".") for r in roots]
    return not any(resolved == b or resolved.startswith(b + os.sep) for b in bases)


def scan_paths(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for f, target in iter_files(paths):
        if target is not None:
            if link_escapes(f, target, paths):
                findings.append(Finding("repo.symlink-escape", "high", f, 0,
                                        f"symlink -> {target}", ["CWE-59", "ASI04", "LLM04:2026"]))
            continue
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
            print(f"{f.severity.upper():8} {f.rule:32} {f.file}:{f.line}  {f.excerpt}  [{', '.join(f.refs)}]")
        print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
