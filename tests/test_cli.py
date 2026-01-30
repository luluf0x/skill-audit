"""Tests for the CLI interface."""

import json

import pytest
from click.testing import CliRunner

from skill_audit.cli import main, scan_path


class TestScanPath:
    """Tests for scan_path function."""

    def test_scans_python_file(self, tmp_path):
        """Test scanning a Python file."""
        file = tmp_path / "test.py"
        file.write_text("eval(user_input)")

        findings = scan_path(file)

        assert len(findings) >= 1
        assert any(f["category"] == "dangerous-builtin" for f in findings)

    def test_scans_directory(self, tmp_path):
        """Test scanning a directory."""
        (tmp_path / "vuln.py").write_text("exec(code)")

        findings = scan_path(tmp_path)

        assert len(findings) >= 1

    def test_deduplicates_findings(self, tmp_path):
        """Test that duplicate findings are removed."""
        # This file might trigger both AST and regex for the same issue
        file = tmp_path / "test.py"
        file.write_text('API_KEY = "sk_live_12345678901234567890"')

        findings = scan_path(file)

        # Check no duplicates (same file, line, category)
        seen = set()
        for f in findings:
            key = (f["file"], f["line"], f["category"])
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)

    def test_sorts_by_severity(self, tmp_path):
        """Test that findings are sorted by severity."""
        file = tmp_path / "test.py"
        file.write_text("""
import subprocess
subprocess.run(['ls'])  # MEDIUM
eval(x)  # CRITICAL
""")

        findings = scan_path(file)

        # CRITICAL should come before MEDIUM
        severities = [f["severity"] for f in findings]
        critical_idx = next(i for i, s in enumerate(severities) if s == "CRITICAL")
        medium_idx = next(i for i, s in enumerate(severities) if s == "MEDIUM")
        assert critical_idx < medium_idx


class TestCLI:
    """Tests for the CLI command."""

    def test_basic_invocation(self, tmp_path):
        """Test basic CLI invocation."""
        file = tmp_path / "safe.py"
        file.write_text("print('hello')")

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path)])

        assert result.exit_code == 0
        assert "Security Score" in result.output

    def test_exit_code_1_for_grade_f(self, tmp_path):
        """Test that grade F results in exit code 1."""
        file = tmp_path / "vuln.py"
        file.write_text("""
eval(x)
exec(y)
import subprocess
subprocess.run(cmd, shell=True)
""")

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path)])

        assert result.exit_code == 1

    def test_json_output(self, tmp_path):
        """Test JSON output format."""
        file = tmp_path / "test.py"
        file.write_text("eval(x)")

        runner = CliRunner()
        result = runner.invoke(main, ["--json", str(tmp_path)])

        # Should be valid JSON
        data = json.loads(result.output)
        assert "findings" in data
        assert "score" in data
        assert "grade" in data
        assert "breakdown" in data

    def test_json_output_structure(self, tmp_path):
        """Test JSON output has correct structure."""
        file = tmp_path / "test.py"
        file.write_text("eval(x)")

        runner = CliRunner()
        result = runner.invoke(main, ["--json", str(tmp_path)])

        data = json.loads(result.output)

        # Check findings structure
        assert len(data["findings"]) >= 1
        finding = data["findings"][0]
        assert "file" in finding
        assert "line" in finding
        assert "severity" in finding
        assert "category" in finding
        assert "message" in finding

        # Check breakdown structure
        assert "CRITICAL" in data["breakdown"]
        assert "count" in data["breakdown"]["CRITICAL"]
        assert "penalty" in data["breakdown"]["CRITICAL"]

    def test_displays_findings_table(self, tmp_path):
        """Test that findings are displayed in a table."""
        file = tmp_path / "test.py"
        file.write_text("eval(x)")

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path)])

        assert "Security Findings" in result.output
        assert "CRITICAL" in result.output

    def test_displays_score_panel(self, tmp_path):
        """Test that score panel is displayed."""
        file = tmp_path / "safe.py"
        file.write_text("print('hello')")

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path)])

        assert "Security Score" in result.output
        assert "Grade" in result.output

    def test_no_findings_message(self, tmp_path):
        """Test message when no findings."""
        file = tmp_path / "safe.py"
        file.write_text("print('hello')")

        runner = CliRunner()
        result = runner.invoke(main, [str(tmp_path)])

        assert "No security issues found" in result.output

    def test_default_path(self):
        """Test that default path is current directory."""
        runner = CliRunner()
        # Just check it runs without error
        result = runner.invoke(main, [])
        # It should run (might have findings or not)
        assert result.exit_code in (0, 1)
