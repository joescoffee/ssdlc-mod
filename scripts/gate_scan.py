#!/usr/bin/env python3
"""SSDLC gate scanner: secrets, dangerous code patterns and AI/agent misconfiguration.

Standard library only, no network, never follows symlinks, never executes anything.

Usage:
    python3 -I gate_scan.py [--json] [--honor-markers] [--files-from FILE] [--] PATH ...

  --json             machine-readable output: {findings, suppressed, skipped, incomplete, honor_markers}
  --honor-markers    apply `ssdlc: allow <reason>` markers. Off by default: the reviewed code
                     can write markers too. Markers never hide secret or invisible-character findings.
  --files-from FILE  read paths from FILE (NUL- or newline-separated), e.g. `git diff -z --name-only`,
                     so file names never pass through a shell.
  --strict           accepted for compatibility; markers are already ignored by default.

Exit status: 0 clean, 1 findings, 2 usage error, 3 no findings but INCOMPLETE
(a path was missing, unreadable, not a regular file, or too large).
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass

MAX_BYTES = 2_000_000
MAX_LINE = 4096  # longer lines are scanned up to this length (bounds regex cost on hostile input)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
ALLOW_MARK = re.compile(r"ssdlc:\s*allow\b[ \t]*(\S.*)?$")
HONOR_MARKERS = False
SUPPRESSED: list[dict] = []
SKIPPED: list[dict] = []
INCOMPLETE_REASONS = ("missing", "unreadable", "not a regular file", "larger than")

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
    ("code.shell-injection", "high", ["CWE-78"], re.compile(r"subprocess\.\w+\([^)]{0,400}shell\s*=\s*True|\bos\.system\(|\bos\.popen\(")),
    ("code.eval", "high", ["CWE-95"], re.compile(r"(?<![\w.])(eval|exec)\s*\(|new\s+Function\s*\(")),
    ("code.unsafe-deserialization", "high", ["CWE-502"], re.compile(
        r"\bpickle\.loads?\(|\bmarshal\.loads?\(|\byaml\.load\((?![^)]{0,400}Loader\s*=\s*yaml\.(Safe|CSafe)Loader)")),
    ("code.sql-string-build", "high", ["CWE-89"], re.compile(
        r"""(?i)\.execute\(\s*(f["']|["'][^"'\n]{0,300}?\b(select|insert|update|delete)\b[^"'\n]{0,300}?["']\s*(%|\+|\.format))""")),
    ("code.tls-verify-disabled", "medium", ["CWE-295"], re.compile(
        r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0")),
    ("code.weak-hash", "medium", ["CWE-328"], re.compile(r"\bhashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]")),
    ("code.insecure-random-token", "low", ["CWE-338"], re.compile(r"(?i)(token|secret|nonce|password)\w{0,40}\s*=\s*.{0,200}?\brandom\.(random|randint|choice)\(")),
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
     re.compile(r"torch\.load\((?![^)]{0,400}weights_only\s*=\s*True)|\bjoblib\.load\(|\bdill\.loads?\(|\bcloudpickle\.loads?\("
                r"|\bread_pickle\(|np\.load\([^)]{0,400}allow_pickle\s*=\s*True|load_model\([^)]{0,400}safe_mode\s*=\s*False")),
    ("ai.agent-approval-bypass", "high", ["LLM03:2026", "ASI02", "ASI09", "CWE-862"],  # DOC (human confirmation; CVE-2025-53773)
     re.compile(r'"chat\.tools\.autoApprove"\s*:\s*true|--dangerously-skip-permissions|"defaultMode"\s*:\s*"bypassPermissions"'
                r'|permission_mode\s*=\s*["\']bypassPermissions|--yolo\b|\bauto_approve\s*=\s*True|"autoApprove"\s*:\s*(true|\[\s*")'
                r'|"alwaysAllow"\s*:\s*\[\s*"')),
    ("ai.open-ended-agent-tool", "high", ["LLM03:2026", "ASI05", "LLM10:2026", "CWE-94"],  # DOC-derived
     re.compile(r"\b(ShellTool|PythonREPLTool|PythonAstREPLTool)\(|allow_dangerous_(code|requests)\s*=\s*True|\b(PALChain|LLMMathChain)\b")),
    ("ai.llm-output-html-sink", "medium", ["LLM10:2026", "CWE-79"],  # DOC-derived
     re.compile(r"dangerouslySetInnerHTML|\bv-html=|\.innerHTML\s*=(?!=)|rehype-raw|allowDangerousHtml\s*:\s*true")),
    ("ai.unpinned-model-ref", "low", ["LLM04:2026", "ASI04", "CWE-494"],  # DOC-derived; may be a deliberate local path
     re.compile(r"\b(from_pretrained|hf_hub_download|snapshot_download)\((?![^)]{0,400}revision\s*=)|ollama\s+(pull|run)\s+\S+:latest\b")),
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
     re.compile(r'"runOn"\s*:\s*"folderOpen"')),
    ("repo.git-config-exec", "high", ["ASI05", "ASI04", "CWE-829"],  # git runs these keys; applied to .git/config* only
     re.compile(r"(?i)^\s*(fsmonitor|hookspath|sshcommand|pager|editor|askpass|external|textconv|clean|smudge|process"
                r"|helper|program|path|gitproxy)\s*=|^\s*[\w.-]+\s*=\s*!")),
    ("ai.prompt-injection-phrase", "info", ["LLM01:2026", "ASI01"],  # STD; reviewers treat it as a lead, not proof
     re.compile(r"(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?)\b")),
]


# Markers never hide these: a secret is a secret whoever annotated it, and hidden characters
# are exactly what a hostile repository would want suppressed.
NEVER_SUPPRESS = ("secret.", "ai.unicode-tag-smuggling", "ai.invisible-or-bidi-chars")
GIT_CONFIG_RULES = {"repo.git-config-exec"}

# Rules whose negative lookahead inspects call arguments: match on the line plus the following
# lines of an unclosed call, so `torch.load(\n f, weights_only=True)` is not a false positive.
SPAN_RULES = {"ai.unsafe-model-load", "ai.unpinned-model-ref", "code.unsafe-deserialization"}
SPAN_LINES = 4
INVISIBLE = re.compile("[\U000E0000-\U000E007F\U000E0100-\U000E01EF\u200B\u200C\u2060\u202A-\u202E\u2066-\u2069]")
CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")
SECRET_RULES = [rx for name, _s, _r, rx in RULES if name.startswith("secret.") and name != "secret.hardcoded-credential"]
QUOTED_VALUE = re.compile(r"""(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|token)\b(\s*[:=]\s*["'])([^"']{4,})(["'])""")


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    excerpt: str
    refs: list[str]


def skip(path: str, reason: str) -> None:
    SKIPPED.append({"file": safe_text(path), "reason": reason})


def safe_text(text: str) -> str:
    """Untrusted text bound for a terminal or a model: no invisible or control characters."""
    text = INVISIBLE.sub(lambda c: f"<U+{ord(c.group(0)):04X}>", text)
    text = re.sub(r"(<U\+E00[0-7][0-9A-F]>)+", "<tag-chars>", text)
    return CONTROL.sub(lambda c: f"\\x{ord(c.group(0)):02x}", text)


def redact(text: str) -> str:
    """Keep the first 4 characters of a secret value."""
    return text[:4] + "…" if len(text) > 4 else "…"


def redact_line(line: str) -> str:
    """Mask every secret on the line, whichever rule produced the finding."""
    for rx in SECRET_RULES:
        line = rx.sub(lambda m: redact(m.group(0)), line)
    return QUOTED_VALUE.sub(lambda m: m.group(1) + m.group(2) + redact(m.group(3)) + m.group(4), line)


def hidden_text(line: str) -> str:
    """Decode Unicode tag characters (U+E0020-E007E) back to the ASCII they hide."""
    return "".join(chr(ord(c) - 0xE0000) for c in line if 0xE0020 <= ord(c) <= 0xE007E)


def excerpt(line: str) -> str:
    hidden = hidden_text(line)
    shown = safe_text(redact_line(line)).strip()
    if hidden:
        return shown[:100] + f"  hidden={safe_text(hidden[:80])!r}"
    return shown[:160]


def call_span(lines: list[str], i: int) -> str:
    """The line plus following lines while its parentheses stay unbalanced."""
    out, depth = [], 0
    for line in lines[i:i + SPAN_LINES]:
        out.append(line[:MAX_LINE].strip())
        depth += line.count("(") - line.count(")")
        if depth <= 0:
            break
    return " ".join(out)


def scan_text(text: str, path: str, only: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    long_lines = 0
    for n, raw in enumerate(lines, 1):
        if len(raw) > MAX_LINE:
            long_lines += 1
        line = raw[:MAX_LINE]
        allow = ALLOW_MARK.search(line) if HONOR_MARKERS else None
        reason = (allow.group(1) or "").strip() if allow else ""
        if allow and reason:
            SUPPRESSED.append({"file": safe_text(path), "line": n, "reason": safe_text(reason)[:120]})
        for rule, sev, refs, rx in RULES:
            if only is not None and rule not in only:
                continue
            if only is None and rule in GIT_CONFIG_RULES:
                continue
            if reason and not rule.startswith(NEVER_SUPPRESS):
                continue
            m = rx.search(line)
            if m and rule in SPAN_RULES and "(" in line:
                m = rx.search(call_span(lines, n - 1))
            if m:
                out.append(Finding(rule, sev, safe_text(path), n, excerpt(line), list(refs)))
    if long_lines:
        skip(path, f"partially scanned: {long_lines} line(s) longer than {MAX_LINE} characters")
    return out


MCP_SECRET_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|auth|credential|^x-.*key$|bearer)")
NPX_PIN = re.compile(r"^(@[\w.-]+/)?[\w.-]+@\d+\.\d+\.\d+")  # exact pkg@1.2.3 or @scope/pkg@1.2.3


def _loads_jsonc(text: str) -> object:
    """JSON with // and /* */ comments and trailing commas (VS Code mcp.json)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True; out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


def _mcp_servers(doc: object) -> dict:
    if not isinstance(doc, dict):
        return {}
    for key in ("mcpServers", "servers", "context_servers", "mcp_servers"):
        v = doc.get(key)
        if isinstance(v, dict):
            return v
    v = doc.get("mcp")  # e.g. {"mcp": {"servers": {...}}}
    return _mcp_servers(v) if isinstance(v, dict) else {}


def scan_mcp_config(text: str, path: str) -> list[Finding]:
    """JSON-aware checks for MCP client configs (.mcp.json, claude_desktop_config.json,
    .vscode/mcp.json, .cursor/mcp.json). OWASP ASI04 / LLM04:2026 / LLM02:2026 / ASI07."""
    if not path.endswith((".json", ".jsonc")) or '"' not in text:
        return []
    try:
        servers = _mcp_servers(_loads_jsonc(text))
    except ValueError:
        if re.search(r'"(mcpServers|servers|context_servers)"', text):
            skip(path, "MCP-looking config could not be parsed")
        return []
    out: list[Finding] = []
    where = safe_text(path)
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        name = safe_text(str(name))
        cmd = str(cfg.get("command", ""))
        raw_args = cfg.get("args", [])
        args = raw_args.split() if isinstance(raw_args, str) else [str(a) for a in raw_args if isinstance(a, (str, int))]
        base = os.path.basename(cmd.replace("\\", "/")).lower()
        if base in ("cmd", "cmd.exe") and args[:1] and args[0].lower() == "/c":
            base, args = os.path.basename(args[1]).lower() if len(args) > 1 else "", args[2:]
        base = re.sub(r"\.(cmd|exe|bat)$", "", base)
        pkgs = [a for a in args if not a.startswith("-")]
        unpinned = None
        if base in ("npx", "bunx", "pnpx") and pkgs and not NPX_PIN.match(pkgs[0]):
            unpinned = f"{base} {pkgs[0]} (no exact @x.y.z version)"
        elif base in ("uvx", "pipx") and pkgs and "==" not in pkgs[-1 if base == "pipx" else 0]:
            unpinned = f"{base} {' '.join(pkgs[:2])} (no ==version)"
        elif any(a.endswith(":latest") or a.endswith("@latest") for a in args):
            unpinned = "floating :latest / @latest"
        if unpinned:
            out.append(Finding("ai.mcp-unpinned", "medium", where, 0,
                               f"server {name!r}: {safe_text(unpinned)}", ["ASI04", "LLM04:2026", "CWE-494"]))
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
        for k, v in {**env, **headers}.items():
            if MCP_SECRET_KEY.search(str(k)) and isinstance(v, str) and len(v) >= 8 and "${" not in v and not v.startswith("$"):
                out.append(Finding("ai.mcp-inline-secret", "high", where, 0,
                                   f"server {name!r}: {safe_text(str(k))}={redact(v)}", ["LLM02:2026", "ASI03", "CWE-798"]))
        url = str(cfg.get("url", cfg.get("serverUrl", "")))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])[:/]", url):
            out.append(Finding("ai.mcp-plaintext-transport", "medium", where, 0,
                               f"server {name!r}: {safe_text(url)}", ["ASI07", "CWE-319"]))
    return out


def iter_files(paths: list[str]):
    """Yield (path, link_target) for entries to scan; symlinks are never followed.

    link_target is set when the entry is a symlink, so the caller can report it without
    reading through it (a planted link to ~/.ssh/id_rsa must not leak).
    """
    for p in paths:
        if os.path.islink(p):
            yield p, os.readlink(p)
        elif os.path.isdir(p):
            def onerror(err: OSError) -> None:
                skip(err.filename or p, f"unreadable directory ({err.strerror})")
            for root, dirs, files in os.walk(p, onerror=onerror):  # followlinks=False
                for d in dirs:
                    full = os.path.join(root, d)
                    if os.path.islink(full):
                        yield full, os.readlink(full)
                    elif d in SKIP_DIRS and d != ".git":
                        skip(full, "directory skipped by default")
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
                for git_file in ("config", "config.worktree"):
                    gc = os.path.join(root, ".git", git_file)
                    if os.path.lexists(gc):  # executable settings live here
                        yield gc, (os.readlink(gc) if os.path.islink(gc) else None)
                for f in sorted(files):
                    full = os.path.join(root, f)
                    yield full, (os.readlink(full) if os.path.islink(full) else None)
        elif os.path.lexists(p):
            yield p, None
        else:
            skip(p, "missing")


def link_escapes(link: str, target: str, roots: list[str]) -> bool:
    resolved = os.path.realpath(os.path.join(os.path.dirname(link), target))
    bases = [os.path.realpath(r if (os.path.isdir(r) and not os.path.islink(r)) else os.path.dirname(r) or ".")
             for r in roots]
    return not any(resolved == b or resolved.startswith(b + os.sep) for b in bases)


def scan_paths(paths: list[str], honor_markers: bool | None = None) -> list[Finding]:
    """Scan files and directories. Resets SUPPRESSED/SKIPPED for each call."""
    global HONOR_MARKERS
    if honor_markers is not None:
        HONOR_MARKERS = honor_markers
    SUPPRESSED.clear()
    SKIPPED.clear()
    findings: list[Finding] = []
    for f, target in iter_files(paths):
        if target is not None:
            if link_escapes(f, target, paths):
                findings.append(Finding("repo.symlink-escape", "high", safe_text(f), 0,
                                        f"symlink -> {safe_text(target)}", ["CWE-59", "ASI04", "LLM04:2026"]))
            continue
        try:
            st = os.lstat(f)
            if not stat.S_ISREG(st.st_mode):
                skip(f, "not a regular file")  # FIFOs, sockets, devices: never opened
                continue
            if st.st_size > MAX_BYTES:
                skip(f, f"larger than {MAX_BYTES} bytes")
                continue
            fd = os.open(f, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as fh:
                data = fh.read()
        except OSError as err:
            skip(f, f"unreadable ({err.strerror})")
            continue
        if b"\0" in data[:4096]:
            skip(f, "binary (NUL byte)")
            continue
        text = data.decode("utf-8", "replace")
        if os.path.basename(f) in ("config", "config.worktree") and os.path.basename(os.path.dirname(f)) == ".git":
            findings.extend(scan_text(text, f, only=GIT_CONFIG_RULES))
            continue
        findings.extend(scan_text(text, f))
        findings.extend(scan_mcp_config(text, f))
    return findings


def is_incomplete() -> bool:
    return any(x["reason"].startswith(INCOMPLETE_REASONS) or "could not be parsed" in x["reason"]
               or x["reason"].startswith("unreadable") for x in SKIPPED)


def parse_args(argv: list[str]) -> tuple[dict, list[str]] | None:
    opts = {"json": False, "honor": False}
    paths: list[str] = []
    it = iter(argv)
    for a in it:
        if a == "--":
            paths.extend(it)
            break
        if a == "--json":
            opts["json"] = True
        elif a == "--honor-markers":
            opts["honor"] = True
        elif a == "--strict":
            pass
        elif a == "--files-from":
            src = next(it, None)
            if src is None:
                return None
            with open(src, "rb") as fh:
                raw = fh.read().decode("utf-8", "surrogateescape")
            paths.extend(p for p in re.split(r"[\0\n]", raw) if p)
        elif a.startswith("--"):
            return None
        else:
            paths.append(a)
    return opts, paths


def main(argv: list[str]) -> int:
    parsed = parse_args(argv)
    if parsed is None or not parsed[1]:
        print(__doc__, file=sys.stderr)
        return 2
    opts, paths = parsed
    findings = scan_paths(paths, honor_markers=opts["honor"])
    incomplete = is_incomplete()
    if opts["json"]:
        print(json.dumps({"findings": [asdict(f) for f in findings], "suppressed": SUPPRESSED,
                          "skipped": SKIPPED, "incomplete": incomplete, "honor_markers": HONOR_MARKERS},
                         ensure_ascii=True, indent=2))
    else:
        for f in findings:
            print(f"{f.severity.upper():8} {f.rule:32} {f.file}:{f.line}  {f.excerpt}  [{', '.join(f.refs)}]")
        for x in SUPPRESSED:
            print(f"SUPPRESSED {x['file']}:{x['line']}  reason: {x['reason']}")
        for x in SKIPPED:
            print(f"SKIPPED   {x['file']}  ({x['reason']})")
        print(f"{len(findings)} finding(s), {len(SUPPRESSED)} suppressed, {len(SKIPPED)} skipped"
              + ("  [INCOMPLETE]" if incomplete else "")
              + ("  [allow markers honored]" if HONOR_MARKERS else ""))
    if findings:
        return 1
    return 3 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
