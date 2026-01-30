"""Tests for the AST-based security scanner."""

import tempfile
from pathlib import Path

import pytest

from skill_audit.ast_scanner import SecurityVisitor, scan_python_file


class TestSecurityVisitor:
    """Tests for SecurityVisitor class."""

    def test_detects_eval(self, tmp_path):
        """Test detection of eval() calls."""
        code = "result = eval(user_input)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["category"] == "dangerous-builtin"
        assert "eval" in findings[0]["message"]

    def test_detects_exec(self, tmp_path):
        """Test detection of exec() calls."""
        code = "exec(code_string)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["category"] == "dangerous-builtin"
        assert "exec" in findings[0]["message"]

    def test_detects_compile(self, tmp_path):
        """Test detection of compile() calls."""
        code = "code = compile(source, '<string>', 'exec')"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "dangerous-builtin"
        assert "compile" in findings[0]["message"]

    def test_detects_os_system(self, tmp_path):
        """Test detection of os.system() calls."""
        code = "import os\nos.system(cmd)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "os-command"
        assert "os.system" in findings[0]["message"]

    def test_detects_os_popen(self, tmp_path):
        """Test detection of os.popen() calls."""
        code = "import os\nos.popen(cmd)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "os-command"
        assert "os.popen" in findings[0]["message"]

    def test_detects_subprocess_shell_true(self, tmp_path):
        """Test detection of subprocess with shell=True."""
        code = "import subprocess\nsubprocess.run(cmd, shell=True)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["category"] == "subprocess-shell"
        assert "shell=True" in findings[0]["message"]

    def test_detects_subprocess_without_shell(self, tmp_path):
        """Test detection of subprocess without shell=True (medium severity)."""
        code = "import subprocess\nsubprocess.run(['ls', '-la'])"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["category"] == "subprocess"

    def test_detects_pickle_load(self, tmp_path):
        """Test detection of pickle.load() calls."""
        code = "import pickle\ndata = pickle.load(f)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "unsafe-deserialization"
        assert "pickle" in findings[0]["message"]

    def test_detects_pickle_loads(self, tmp_path):
        """Test detection of pickle.loads() calls."""
        code = "import pickle\ndata = pickle.loads(data)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "unsafe-deserialization"

    def test_detects_unsafe_yaml_load(self, tmp_path):
        """Test detection of yaml.load() without SafeLoader."""
        code = "import yaml\ndata = yaml.load(content)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["category"] == "unsafe-yaml"

    def test_allows_safe_yaml_load(self, tmp_path):
        """Test that yaml.load() with SafeLoader is not flagged."""
        code = "import yaml\ndata = yaml.load(content, Loader=yaml.SafeLoader)"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 0

    def test_no_findings_for_safe_code(self, tmp_path):
        """Test that safe code produces no findings."""
        code = """
def add(a, b):
    return a + b

def greet(name):
    print(f"Hello, {name}")
"""
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 0

    def test_handles_syntax_error(self, tmp_path):
        """Test that syntax errors return empty list."""
        code = "def broken(:\n    pass"
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert findings == []

    def test_handles_missing_file(self, tmp_path):
        """Test that missing files return empty list."""
        file = tmp_path / "nonexistent.py"

        findings = scan_python_file(file)

        assert findings == []

    def test_finding_includes_line_number(self, tmp_path):
        """Test that findings include correct line numbers."""
        code = """# line 1
# line 2
result = eval(x)  # line 3
"""
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert findings[0]["line"] == 3

    def test_finding_includes_file_path(self, tmp_path):
        """Test that findings include the file path."""
        code = "eval(x)"
        file = tmp_path / "myfile.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 1
        assert "myfile.py" in findings[0]["file"]

    def test_multiple_findings_in_one_file(self, tmp_path):
        """Test detection of multiple vulnerabilities in one file."""
        code = """
eval(x)
exec(y)
os.system(cmd)
"""
        file = tmp_path / "test.py"
        file.write_text(code)

        findings = scan_python_file(file)

        assert len(findings) == 3
        categories = {f["category"] for f in findings}
        assert "dangerous-builtin" in categories
        assert "os-command" in categories
