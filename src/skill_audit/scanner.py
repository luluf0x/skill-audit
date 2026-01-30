"""Security scanner for agent skills."""
import re
from pathlib import Path
from typing import List, Dict, Any

# Detection patterns: (regex, severity, type, description)
PATTERNS = {
    'shell': [
        (r'\bos\.system\s*\(', 'HIGH', 'shell-exec', 'os.system() - command injection risk'),
        (r'\bsubprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True', 'CRITICAL', 'shell-exec', 'subprocess with shell=True - command injection'),
        (r'\beval\s*\(', 'CRITICAL', 'code-exec', 'eval() - arbitrary code execution'),
        (r'\bexec\s*\(', 'CRITICAL', 'code-exec', 'exec() - arbitrary code execution'),
        (r'`[^`]*\$', 'HIGH', 'shell-exec', 'Shell variable in backticks - injection risk'),
        (r'\$\([^)]+\)', 'MEDIUM', 'shell-exec', 'Command substitution - check input sanitization'),
    ],
    'exfiltration': [
        (r'requests\.(get|post)\s*\([^)]*\+', 'HIGH', 'exfil', 'HTTP request with concatenation - data exfil risk'),
        (r'curl\s+[^|]*\$', 'HIGH', 'exfil', 'curl with variable - data exfiltration risk'),
        (r'wget\s+[^|]*\$', 'HIGH', 'exfil', 'wget with variable - data exfiltration risk'),
        (r'(api_key|password|secret|token)\s*=', 'MEDIUM', 'secret', 'Hardcoded secret - credential exposure'),
        (r'\.env\b', 'LOW', 'env', 'Environment file access - check what\'s exposed'),
    ],
    'prompt_injection': [
        (r'(read|cat|open)\s*\([^)]+\)\s*.*\.(prompt|send|complete)', 'HIGH', 'prompt-inject', 'File content passed to LLM - prompt injection surface'),
        (r'user_input.*\.(prompt|message|content)', 'MEDIUM', 'prompt-inject', 'User input in prompt - potential injection'),
    ],
    'file_access': [
        (r'open\s*\([^)]*["\']w', 'MEDIUM', 'file-write', 'File write operation - check path sanitization'),
        (r'(rm|unlink|remove)\s+(-rf?\s+)?["\']?/', 'CRITICAL', 'destructive', 'Destructive file operation on absolute path'),
        (r'chmod\s+777', 'HIGH', 'permissions', 'World-writable permissions'),
        (r'sudo\b', 'HIGH', 'privilege', 'Sudo usage - privilege escalation'),
    ],
    'network': [
        (r'0\.0\.0\.0', 'MEDIUM', 'network', 'Binding to all interfaces'),
        (r'socket\.socket\s*\(', 'LOW', 'network', 'Raw socket usage'),
    ],
    'dependencies': [
        (r'pip install\s+[^=]+$', 'MEDIUM', 'deps', 'Unpinned pip dependency'),
        (r'npm install\s+[^@]+$', 'MEDIUM', 'deps', 'Unpinned npm dependency'),
    ]
}

# File extensions to scan
SCAN_EXTENSIONS = {'.py', '.sh', '.bash', '.js', '.ts', '.md', '.yaml', '.yml', '.json'}


def scan_file(file_path: Path) -> List[Dict[str, Any]]:
    """Scan a single file for security issues."""
    findings = []
    
    try:
        content = file_path.read_text(errors='ignore')
        lines = content.split('\n')
    except Exception:
        return findings
    
    for line_num, line in enumerate(lines, 1):
        # Skip comments (basic)
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue
            
        for category, patterns in PATTERNS.items():
            for pattern, severity, finding_type, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'severity': severity,
                        'type': finding_type,
                        'category': category,
                        'file': str(file_path),
                        'line': line_num,
                        'description': description,
                        'snippet': line.strip()[:80]
                    })
    
    return findings


def scan_skill(skill_path: Path) -> List[Dict[str, Any]]:
    """Scan an entire skill directory."""
    findings = []
    
    if skill_path.is_file():
        return scan_file(skill_path)
    
    for file_path in skill_path.rglob('*'):
        if file_path.is_file() and file_path.suffix in SCAN_EXTENSIONS:
            # Skip node_modules, venv, etc
            if any(skip in str(file_path) for skip in ['node_modules', 'venv', '.venv', '__pycache__', '.git']):
                continue
            findings.extend(scan_file(file_path))
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings.sort(key=lambda x: severity_order.get(x['severity'], 99))
    
    return findings


def get_security_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate a security score (0-100, higher is better)."""
    if not findings:
        return 100
    
    deductions = {
        'CRITICAL': 30,
        'HIGH': 15,
        'MEDIUM': 5,
        'LOW': 1
    }
    
    score = 100
    for f in findings:
        score -= deductions.get(f['severity'], 0)
    
    return max(0, score)
