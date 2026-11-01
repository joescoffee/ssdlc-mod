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

    def test_allow_marker(self):
        self.assertEqual(gate_scan.scan_text("os.system(cmd)  # ssdlc: allow reviewed", "t"), [])


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
        self.assertGreaterEqual(len(json.loads(r.stdout)), 7)

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


if __name__ == "__main__":
    unittest.main()
