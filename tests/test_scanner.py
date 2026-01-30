"""Tests for the regex-based scanner."""

import pytest
from pathlib import Path

from skill_audit.scanner import (
    PATTERNS,
    scan_directory,
    scan_file_with_regex,
    should_scan_file,
)


class TestShouldScanFile:
    """Tests for should_scan_file function."""

    def test_python_files_scanned(self, tmp_path):
        """Test that Python files are scanned."""
        assert should_scan_file(Path("test.py"))
        assert should_scan_file(Path("src/main.py"))

    def test_javascript_files_scanned(self):
        """Test that JavaScript files are scanned."""
        assert should_scan_file(Path("app.js"))
        assert should_scan_file(Path("component.jsx"))
        assert should_scan_file(Path("main.ts"))
        assert should_scan_file(Path("component.tsx"))

    def test_config_files_scanned(self):
        """Test that config files are scanned."""
        assert should_scan_file(Path("config.yaml"))
        assert should_scan_file(Path("config.yml"))
        assert should_scan_file(Path("config.json"))
        assert should_scan_file(Path("settings.toml"))

    def test_hidden_files_skipped(self):
        """Test that hidden files are skipped."""
        assert not should_scan_file(Path(".hidden.py"))
        assert not should_scan_file(Path(".git/config"))

    def test_pycache_skipped(self):
        """Test that __pycache__ is skipped."""
        assert not should_scan_file(Path("__pycache__/module.pyc"))

    def test_node_modules_skipped(self):
        """Test that node_modules is skipped."""
        assert not should_scan_file(Path("node_modules/pkg/index.js"))

    def test_venv_skipped(self):
        """Test that virtual environments are skipped."""
        assert not should_scan_file(Path(".venv/lib/site.py"))
        assert not should_scan_file(Path("venv/lib/site.py"))

    def test_unsupported_extensions_skipped(self):
        """Test that unsupported file types are skipped."""
        assert not should_scan_file(Path("image.png"))
        assert not should_scan_file(Path("data.csv"))
        assert not should_scan_file(Path("archive.zip"))


class TestScanFileWithRegex:
    """Tests for scan_file_with_regex function."""

    def test_detects_hardcoded_api_key(self, tmp_path):
        """Test detection of hardcoded API keys."""
        file = tmp_path / "config.py"
        file.write_text('API_KEY = "my_secret_api_key_value_12345678"')

        findings = scan_file_with_regex(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "hardcoded-secret"

    def test_detects_hardcoded_password(self, tmp_path):
        """Test detection of hardcoded passwords."""
        file = tmp_path / "config.py"
        file.write_text('PASSWORD = "supersecretpassword123"')

        findings = scan_file_with_regex(file)

        assert len(findings) == 1
        assert findings[0]["category"] == "hardcoded-secret"

    def test_detects_aws_key(self, tmp_path):
        """Test detection of AWS access keys."""
        file = tmp_path / "config.py"
        file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"')

        findings = scan_file_with_regex(file)

        aws_findings = [f for f in findings if f["category"] == "aws-key"]
        assert len(aws_findings) == 1
        assert aws_findings[0]["severity"] == "CRITICAL"

    def test_detects_private_key(self, tmp_path):
        """Test detection of private keys."""
        file = tmp_path / "key.pem"
        file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")

        findings = scan_file_with_regex(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["category"] == "private-key"

    def test_detects_credentials_in_url(self, tmp_path):
        """Test detection of credentials in URLs."""
        file = tmp_path / "config.py"
        file.write_text('DB_URL = "postgres://user:password@localhost/db"')

        findings = scan_file_with_regex(file)

        url_findings = [f for f in findings if f["category"] == "credentials-in-url"]
        assert len(url_findings) == 1
        assert url_findings[0]["severity"] == "HIGH"

    def test_no_false_positives_for_safe_code(self, tmp_path):
        """Test that normal code doesn't trigger false positives."""
        file = tmp_path / "app.py"
        file.write_text("""
def add(a, b):
    return a + b

name = "John"
count = 42
""")

        findings = scan_file_with_regex(file)

        assert len(findings) == 0

    def test_handles_missing_file(self, tmp_path):
        """Test that missing files return empty list."""
        file = tmp_path / "nonexistent.py"

        findings = scan_file_with_regex(file)

        assert findings == []

    def test_includes_line_number(self, tmp_path):
        """Test that findings include correct line numbers."""
        file = tmp_path / "config.py"
        file.write_text("""# line 1
# line 2
API_KEY = "sk_test_1234567890abcdef"
""")

        findings = scan_file_with_regex(file)

        assert len(findings) == 1
        assert findings[0]["line"] == 3


class TestScanDirectory:
    """Tests for scan_directory function."""

    def test_scans_single_file(self, tmp_path):
        """Test scanning a single file."""
        file = tmp_path / "config.py"
        file.write_text('SECRET_KEY = "mysecretkey12345678"')

        findings = scan_directory(file)

        assert len(findings) >= 1

    def test_scans_directory_recursively(self, tmp_path):
        """Test recursive directory scanning."""
        subdir = tmp_path / "src"
        subdir.mkdir()
        (subdir / "config.py").write_text('API_KEY = "key123456789012345"')
        (tmp_path / "main.py").write_text('PASSWORD = "pass123456789012"')

        findings = scan_directory(tmp_path)

        assert len(findings) >= 2

    def test_skips_excluded_directories(self, tmp_path):
        """Test that excluded directories are skipped."""
        venv = tmp_path / ".venv"
        venv.mkdir()
        (venv / "site.py").write_text('PASSWORD = "secret12345678901"')

        findings = scan_directory(tmp_path)

        assert len(findings) == 0

    def test_empty_directory(self, tmp_path):
        """Test scanning an empty directory."""
        findings = scan_directory(tmp_path)

        assert findings == []
