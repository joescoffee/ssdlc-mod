#!/usr/bin/env python3
"""SSDLC gate scanner: secrets and dangerous code patterns.

Standard library only, no network. Usage:
    python3 -I gate_scan.py [--json] [--strict] PATH [PATH ...]

--strict ignores `ssdlc: allow <reason>` markers; use it on any repository you
do not trust, since the reviewed code can carry markers too.
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
ALLOW_MARK = re.compile(r"ssdlc:\s*allow\b[ \t]*(\S.*)?$")
# Markers live in the reviewed code, so a hostile repo can write them too (ASI01/ASI09):
# a marker needs a reason, every suppression is reported, and --strict ignores markers.
STRICT = False
SUPPRESSED: list[dict] = []
SKIPPED: list[dict] = []

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
    # --- AI / LLM / agent rules (OWASP LLM Top 10 2026, Agentic Top 10 2026).
    # Provenance per rule: DOC = stated in the OWASP 2026 text, STD = standard practice.
    ("ai.unicode-tag-smuggling", "high", ["LLM01:2026", "ASI01", "CWE-1427"],  # DOC: ASCII smuggling
     re.compile("[\U000E0000-\U000E007F\U000E0100-\U000E01EF]")),
    ("ai.invisible-or-bidi-chars", "medium", ["LLM01:2026", "CWE-1007"],  # DOC zero-width / STD bidi (Trojan Source)
     re.compile("[\u200B\u200C\u2060\u202A-\u202E\u2066-\u2069]")),
    ("ai.trust-remote-code", "high", ["LLM04:2026", "ASI04", "CWE-494"],  # STD
     re.compile(r"trust_remote_code\s*=\s*True|--trust-remote-code\b")),
    ("ai.dangerous-deserialization-flag", "high", ["LLM04:2026", "LLM09:2026", "CWE-502"],  # STD
     re.compile(r"allow_dangerous_deserialization\s*=\s*True")),
    ("ai.unsafe-model-load", "high", ["LLM04:2026", "LLM05:2026", "CWE-502"],  # DOC (CVE-2025-32434: also need torch>=2.6)
     re.compile(r"torch\.load\((?![^)]*weights_only\s*=\s*True)|\bjoblib\.load\(|\bdill\.loads?\(|\bcloudpickle\.loads?\("
                r"|\bread_pickle\(|np\.load\([^)]*allow_pickle\s*=\s*True|load_model\([^)]*safe_mode\s*=\s*False")),
    ("ai.agent-approval-bypass", "high", ["LLM03:2026", "ASI02", "ASI09", "CWE-862"],  # DOC (human confirmation; CVE-2025-53773)
     re.compile(r'"chat\.tools\.autoApprove"\s*:\s*true|--dangerously-skip-permissions|"defaultMode"\s*:\s*"bypassPermissions"'
                r'|permission_mode\s*=\s*["\']bypassPermissions|--yolo\b|\bauto_approve\s*=\s*True|"autoApprove"\s*:\s*(true|\[\s*")'
                r'|"alwaysAllow"\s*:\s*\[\s*"')),
    ("ai.open-ended-agent-tool", "high", ["LLM03:2026", "ASI05", "LLM10:2026", "CWE-94"],  # DOC-derived
     re.compile(r"\b(ShellTool|PythonREPLTool|PythonAstREPLTool)\(|allow_dangerous_(code|requests)\s*=\s*True|\b(PALChain|LLMMathChain)\b")),
    ("ai.llm-output-html-sink", "medium", ["LLM10:2026", "CWE-79"],  # DOC-derived
     re.compile(r"dangerouslySetInnerHTML|\bv-html=|\.innerHTML\s*=(?!=)|rehype-raw|allowDangerousHtml\s*:\s*true")),
    ("ai.unpinned-model-ref", "low", ["LLM04:2026", "ASI04", "CWE-494"],  # DOC-derived; may be a deliberate local path
     re.compile(r"\b(from_pretrained|hf_hub_download|snapshot_download)\((?![^)]*revision\s*=)|ollama\s+(pull|run)\s+\S+:latest\b")),
    ("ai.exposed-ml-dashboard", "medium", ["LLM04:2026", "LLM06:2026", "LLM09:2026", "CWE-306"],  # DOC (ShadowRay) / STD (Weaviate)
     re.compile(r"--dashboard-host[= ]0\.0\.0\.0|dashboard_host\s*=\s*[\"']0\.0\.0\.0|AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED\s*[:=]\s*[\"']?true")),
    ("ai.langchain-loads", "medium", ["LLM10:2026", "CWE-502"],  # DOC (refs CVE-2025-68664)
     re.compile(r"from\s+langchain(_core)?\.load\s+import\s+(load|loads)\b|langchain(_core)?\.load\.loads?\(")),
    ("ai.unbounded-agent", "low", ["LLM06:2026", "ASI08", "CWE-770"],  # DOC-derived
     re.compile(r"max_iterations\s*=\s*None|max_(output_|completion_)?tokens\s*[=:]\s*(None|-1|\d{6,})\b|recursion_limit\s*[:=]\s*\d{4,}")),
    ("ai.agent-wildcard-allowlist", "high", ["ASI02", "ASI03", "LLM03:2026", "CWE-250"],  # STD (Claude Code settings syntax)
     re.compile(r'"(Bash|Bash\(\*\)|Bash\(curl:\*\)|Bash\(wget:\*\)|Bash\(ping:\*\)|mcp__\*|WebFetch|\*)"\s*[,\]]'
                r'|"enableAllProjectMcpServers"\s*:\s*true|approval_policy\s*=\s*["\']never|"trust"\s*:\s*true')),
    ("ai.agent-unsandboxed-exec", "high", ["ASI05", "LLM03:2026", "CWE-250"],  # STD (AutoGen / Open Interpreter)
     re.compile(r'["\']?use_docker["\']?\s*[:=]\s*False|\bauto_run\s*=\s*True')),
    ("ai.open-time-exec", "high", ["ASI05", "ASI04", "CWE-829"],  # DOC (App D: config executed on open)
     re.compile(r'"runOn"\s*:\s*"folderOpen"|^\s*fsmonitor\s*=|^\s*hooksPath\s*=')),
    ("ai.prompt-injection-phrase", "info", ["LLM01:2026", "ASI01"],  # STD; reviewers treat it as a lead, not proof
     re.compile(r"(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?)\b")),
]


# Rules whose negative lookahead inspects call arguments: match on the line plus
# the following lines of an unclosed call, so `torch.load(\n f, weights_only=True)`
# is not a false positive.
SPAN_RULES = {"ai.unsafe-model-load", "ai.unpinned-model-ref", "code.unsafe-deserialization"}
SPAN_LINES = 4
INVISIBLE = re.compile("[\U000E0000-\U000E007F\U000E0100-\U000E01EF\u200B\u200C\u2060\u202A-\u202E\u2066-\u2069]")


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


def hidden_text(line: str) -> str:
    """Decode Unicode tag characters (U+E0020-E007E) back to the ASCII they hide."""
    return "".join(chr(ord(c) - 0xE0000) for c in line if 0xE0020 <= ord(c) <= 0xE007E)


def excerpt(line: str, rule: str, m: re.Match[str]) -> str:
    """Code findings keep their evidence verbatim; secret findings hide the value;
    invisible characters are shown as code points, never echoed raw."""
    if rule.startswith("secret."):
        line = line[: m.start()] + redact(m.group(0)) + line[m.end():]
    if INVISIBLE.search(line):
        hidden = hidden_text(line)
        line = INVISIBLE.sub(lambda c: f"<U+{ord(c.group(0)):04X}>", line)
        line = re.sub(r"(<U\+E00[0-7][0-9A-F]>)+", "<tag-chars>", line)
        if hidden:
            return (line.strip()[:100] + f"  hidden={hidden[:80]!r}")
    return line.strip()[:160]


def call_span(lines: list[str], i: int) -> str:
    """The line plus following lines while its parentheses stay unbalanced."""
    out, depth = [], 0
    for line in lines[i:i + SPAN_LINES]:
        out.append(line.strip())
        depth += line.count("(") - line.count(")")
        if depth <= 0:
            break
    return " ".join(out)


GIT_CONFIG_RULES = {"ai.open-time-exec"}


def scan_text(text: str, path: str, only: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        allow = ALLOW_MARK.search(line)
        if allow and not STRICT and (allow.group(1) or "").strip():
            SUPPRESSED.append({"file": path, "line": n, "reason": allow.group(1).strip()[:120]})
            continue
        for rule, sev, refs, rx in RULES:
            if only is not None and rule not in only:
                continue
            m = rx.search(line)
            if m and rule in SPAN_RULES and "(" in line:
                m = rx.search(call_span(lines, n - 1))
            if m:
                out.append(Finding(rule, sev, path, n, excerpt(line, rule, m), list(refs)))
    return out


MCP_SECRET_KEY = re.compile(r"(?i)(token|secret|password|passwd|api_?key|auth|credential)")
NPX_PIN = re.compile(r"^(@[\w.-]+/)?[\w.-]+@\d")  # pkg@1.2.3 or @scope/pkg@1.2.3


def _mcp_servers(doc: object) -> dict:
    if not isinstance(doc, dict):
        return {}
    for key in ("mcpServers", "servers", "context_servers"):
        v = doc.get(key)
        if isinstance(v, dict):
            return v
    v = doc.get("mcp")  # e.g. {"mcp": {"servers": {...}}}
    return _mcp_servers(v) if isinstance(v, dict) else {}


def scan_mcp_config(text: str, path: str) -> list[Finding]:
    """JSON-aware checks for MCP client configs (.mcp.json, claude_desktop_config.json,
    .vscode/mcp.json, .cursor/mcp.json). OWASP ASI04 / LLM04:2026 / LLM02:2026 / ASI07."""
    if not path.endswith(".json") or '"' not in text:
        return []
    try:
        servers = _mcp_servers(json.loads(text))
    except ValueError:
        return []
    out: list[Finding] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int))]
        base = os.path.basename(cmd)
        pkgs = [a for a in args if not a.startswith("-")]
        unpinned = None
        if base in ("npx", "bunx", "pnpx") and pkgs and not NPX_PIN.match(pkgs[0]):
            unpinned = f"{base} {pkgs[0]} (no @version)"
        elif base in ("uvx", "pipx") and pkgs and "==" not in pkgs[-1 if base == "pipx" else 0]:
            unpinned = f"{base} {' '.join(pkgs[:2])} (no ==version)"
        elif any(a.endswith(":latest") or a.endswith("@latest") for a in args):
            unpinned = "floating :latest / @latest"
        if unpinned:
            out.append(Finding("ai.mcp-unpinned", "medium", path, 0,
                               f"server {name!r}: {unpinned}", ["ASI04", "LLM04:2026", "CWE-494"]))
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        for k, v in {**env, **headers}.items():
            if MCP_SECRET_KEY.search(k) and isinstance(v, str) and len(v) >= 8 and "${" not in v and not v.startswith("$"):
                out.append(Finding("ai.mcp-inline-secret", "high", path, 0,
                                   f"server {name!r}: {k}={redact(v)}", ["LLM02:2026", "ASI03", "CWE-798"]))
        url = str(cfg.get("url", cfg.get("serverUrl", "")))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])[:/]", url):
            out.append(Finding("ai.mcp-plaintext-transport", "medium", path, 0,
                               f"server {name!r}: {url}", ["ASI07", "CWE-319"]))
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
                for d in dirs:
                    if d in SKIP_DIRS and d != ".git":
                        SKIPPED.append({"file": os.path.join(root, d), "reason": "directory skipped by default"})
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                git_config = os.path.join(root, ".git", "config")
                if os.path.isfile(git_config) and not os.path.islink(git_config):
                    yield git_config, None  # executable settings (fsmonitor, hooksPath) live here
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
                SKIPPED.append({"file": f, "reason": f"larger than {MAX_BYTES} bytes"})
                continue
            with open(f, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            SKIPPED.append({"file": f, "reason": "binary (NUL byte)"})
            continue
        text = data.decode("utf-8", "replace")
        if f.endswith(os.sep + ".git" + os.sep + "config"):
            findings.extend(scan_text(text, f, only=GIT_CONFIG_RULES))
            continue
        findings.extend(scan_text(text, f))
        findings.extend(scan_mcp_config(text, f))
    return findings


def main(argv: list[str]) -> int:
    global STRICT
    as_json = "--json" in argv
    STRICT = "--strict" in argv
    paths = [a for a in argv if a not in ("--json", "--strict")]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    findings = scan_paths(paths)
    if as_json:
        print(json.dumps({"findings": [asdict(f) for f in findings], "suppressed": SUPPRESSED,
                          "skipped": SKIPPED, "strict": STRICT}, ensure_ascii=False, indent=2))
    else:
        for f in findings:
            print(f"{f.severity.upper():8} {f.rule:32} {f.file}:{f.line}  {f.excerpt}  [{', '.join(f.refs)}]")
        for x in SUPPRESSED:
            print(f"SUPPRESSED {x['file']}:{x['line']}  reason: {x['reason']}")
        for x in SKIPPED:
            print(f"SKIPPED   {x['file']}  ({x['reason']})")
        print(f"{len(findings)} finding(s), {len(SUPPRESSED)} suppressed, {len(SKIPPED)} skipped"
              + ("  [strict: allow markers ignored]" if STRICT else ""))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
