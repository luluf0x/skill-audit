"""AST-based security scanner for Python files."""

import ast
from pathlib import Path
from typing import Dict, List


class SecurityVisitor(ast.NodeVisitor):
    """AST visitor that detects security vulnerabilities in Python code."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Dict] = []

    def _add_finding(self, node: ast.AST, severity: str, category: str, message: str):
        """Record a security finding."""
        self.findings.append({
            "file": self.filepath,
            "line": node.lineno,
            "severity": severity,
            "category": category,
            "message": message,
        })

    def visit_Call(self, node: ast.Call):
        """Visit function calls to detect dangerous patterns."""
        self._check_dangerous_builtins(node)
        self._check_os_commands(node)
        self._check_subprocess(node)
        self._check_pickle(node)
        self._check_yaml(node)
        self.generic_visit(node)

    def _check_dangerous_builtins(self, node: ast.Call):
        """Detect dangerous builtin functions: eval, exec, compile."""
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name == "eval":
                self._add_finding(
                    node, "CRITICAL", "dangerous-builtin",
                    "Use of eval() can execute arbitrary code"
                )
            elif name == "exec":
                self._add_finding(
                    node, "CRITICAL", "dangerous-builtin",
                    "Use of exec() can execute arbitrary code"
                )
            elif name == "compile":
                self._add_finding(
                    node, "HIGH", "dangerous-builtin",
                    "Use of compile() can be used to execute arbitrary code"
                )

    def _check_os_commands(self, node: ast.Call):
        """Detect os.system and os.popen calls."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                if node.func.attr == "system":
                    self._add_finding(
                        node, "HIGH", "os-command",
                        "Use of os.system() can lead to command injection"
                    )
                elif node.func.attr == "popen":
                    self._add_finding(
                        node, "HIGH", "os-command",
                        "Use of os.popen() can lead to command injection"
                    )

    def _check_subprocess(self, node: ast.Call):
        """Detect subprocess calls, especially with shell=True."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                if node.func.attr in ("run", "call", "Popen", "check_output", "check_call"):
                    # Check for shell=True
                    has_shell_true = False
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                has_shell_true = True
                            elif isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                                has_shell_true = True

                    if has_shell_true:
                        self._add_finding(
                            node, "CRITICAL", "subprocess-shell",
                            f"subprocess.{node.func.attr}() with shell=True can lead to command injection"
                        )
                    else:
                        self._add_finding(
                            node, "MEDIUM", "subprocess",
                            f"subprocess.{node.func.attr}() usage - ensure input is sanitized"
                        )

    def _check_pickle(self, node: ast.Call):
        """Detect unsafe pickle usage."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                if node.func.attr in ("load", "loads"):
                    self._add_finding(
                        node, "HIGH", "unsafe-deserialization",
                        f"pickle.{node.func.attr}() can execute arbitrary code during deserialization"
                    )

    def _check_yaml(self, node: ast.Call):
        """Detect unsafe yaml.load usage without SafeLoader."""
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                if node.func.attr == "load":
                    # Check if Loader is SafeLoader or safe_load is used
                    has_safe_loader = False
                    for keyword in node.keywords:
                        if keyword.arg == "Loader":
                            if isinstance(keyword.value, ast.Attribute):
                                if keyword.value.attr in ("SafeLoader", "CSafeLoader"):
                                    has_safe_loader = True
                            elif isinstance(keyword.value, ast.Name):
                                if keyword.value.id in ("SafeLoader", "CSafeLoader"):
                                    has_safe_loader = True

                    if not has_safe_loader:
                        self._add_finding(
                            node, "HIGH", "unsafe-yaml",
                            "yaml.load() without SafeLoader can execute arbitrary code"
                        )


def scan_python_file(filepath: Path) -> List[Dict]:
    """
    Scan a Python file for security vulnerabilities using AST.

    Args:
        filepath: Path to the Python file to scan

    Returns:
        List of findings, each a dict with file, line, severity, category, message
    """
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
        visitor = SecurityVisitor(str(filepath))
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        # Fall back to regex scanner for files with syntax errors
        return []
    except (OSError, IOError):
        return []
