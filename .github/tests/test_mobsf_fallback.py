"""Exercise the workflow's partial-report branch without running the scanner."""
import contextlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


class PartialFindingsTest(unittest.TestCase):
    def test_errors_with_findings_do_not_log_source(self):
        workflow = (Path(__file__).parents[1] / "workflows/security.yml").read_text()
        start = workflow.index("          if errors or plist_failures.messages:")
        end = workflow.index("\n          sarif.sarif_output", start)
        code = "\n".join(line[10:] for line in workflow[start:end].splitlines())
        secret = "SECRET_MATCHED_SOURCE"
        results = {"results": {"rule": {"metadata": {"description": secret}, "files": [
            {"file_path": "source.swift", "match_lines": [4, 7], "match_string": secret}
        ]}}}
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit) as exit_result:
                exec(compile(code, "workflow-fallback", "exec"), {
                    "results": results, "errors": [{"message": secret}],
                    "plist_failures": SimpleNamespace(messages=[secret]), "json": json, "sys": sys,
                })
        self.assertEqual(exit_result.exception.code, 1)
        self.assertNotIn(secret, output.getvalue() + errors.getvalue())
        findings = json.loads(output.getvalue().removeprefix("Partial MobSF findings: "))
        self.assertEqual(findings, [{"rule_id": "rule", "file_path": "source.swift", "match_lines": [4, 7]}])


if __name__ == "__main__":
    unittest.main()
