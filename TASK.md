# TASK: Implement AST Scanner and Security Score

You are adding two features to `skill-audit`, a Python CLI tool that scans agent skills for security vulnerabilities.

## Repository Context

- **Location:** `/home/ubuntu/clawd/tools/skill-audit`
- **Existing files:**
  - `src/skill_audit/cli.py` — CLI entry point using Click + Rich
  - `src/skill_audit/scanner.py` — Current regex-based scanner
  - `pyproject.toml` — Project config

## Task 1: Create `src/skill_audit/ast_scanner.py`

### Purpose
Parse Python files using the `ast` module to detect dangerous patterns with proper context awareness (ignores comments, understands function calls).

### Requirements

1. **Create a `SecurityVisitor` class** that extends `ast.NodeVisitor`

2. **Detect these dangerous function calls:**

| Function | Severity | Type | Description |
|----------|----------|------|-------------|
| `eval()` | CRITICAL | code-exec | Arbitrary code execution |
| `exec()` | CRITICAL | code-exec | Arbitrary code execution |
| `compile()` | HIGH | code-exec | Code compilation |
| `os.system()` | HIGH | shell-exec | Command injection risk |
| `os.popen()` | HIGH | shell-exec | Command injection risk |
| `subprocess.run()` with `shell=True` | CRITICAL | shell-exec | Command injection |
| `subprocess.call()` with `shell=True` | CRITICAL | shell-exec | Command injection |
| `subprocess.Popen()` with `shell=True` | CRITICAL | shell-exec | Command injection |
| `subprocess.*()` without `shell=True` | MEDIUM | shell-exec | Verify input sanitization |
| `pickle.loads()` / `pickle.load()` | HIGH | deserial | Unsafe deserialization |
| `yaml.load()` without SafeLoader | HIGH | deserial | Unsafe deserialization |

3. **Implement these methods:**

```python
def scan_python_file(filepath: Path) -> List[Dict[str, Any]]:
    """
    Scan a Python file using AST.
    
    Returns list of findings, each with keys:
    - severity: str ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    - type: str (e.g., 'code-exec', 'shell-exec', 'deserial')
    - file: str (filepath)
    - line: int (line number)
    - description: str (human-readable description)
    
    On SyntaxError, return empty list (caller falls back to regex).
    """
```

4. **Helper method to extract function names:**
   - `ast.Name` → simple function like `eval`
   - `ast.Attribute` → chained like `os.system`, `subprocess.run`

5. **Helper method to check for `shell=True`:**
   - Inspect `node.keywords` for keyword arg `shell` with value `True`

### Example Output

```python
[
    {
        'severity': 'CRITICAL',
        'type': 'code-exec',
        'file': 'vuln.py',
        'line': 14,
        'description': 'eval() - arbitrary code execution'
    },
    {
        'severity': 'CRITICAL', 
        'type': 'shell-exec',
        'file': 'vuln.py',
        'line': 22,
        'description': 'subprocess.run() with shell=True - command injection'
    }
]
```

---

## Task 2: Create `src/skill_audit/score.py`

### Purpose
Calculate a security score (0-100) based on findings. Higher = more secure.

### Scoring Rules

```python
SEVERITY_WEIGHTS = {
    'CRITICAL': 25,
    'HIGH': 10,
    'MEDIUM': 3,
    'LOW': 1,
}

# Cap deductions so one bad file doesn't completely tank the score
SEVERITY_CAPS = {
    'CRITICAL': 50,  # Max -50 from criticals
    'HIGH': 30,      # Max -30 from highs
    'MEDIUM': 15,    # Max -15 from mediums
    'LOW': 5,        # Max -5 from lows
}
```

### Required Function

```python
def calculate_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate security score from findings.
    
    Args:
        findings: List of finding dicts with 'severity' key
        
    Returns:
        {
            'score': int,           # 0-100
            'grade': str,           # 'A', 'B', 'C', 'D', 'F'
            'breakdown': {
                'CRITICAL': {'count': int, 'deduction': int},
                'HIGH': {'count': int, 'deduction': int},
                'MEDIUM': {'count': int, 'deduction': int},
                'LOW': {'count': int, 'deduction': int},
            },
            'summary': str          # e.g., "Found 2 critical, 1 high severity issues"
        }
    """
```

### Grade Scale

| Score | Grade |
|-------|-------|
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

---

## Task 3: Integrate into CLI

### Update `src/skill_audit/cli.py`

1. **Import the new modules:**
```python
from .ast_scanner import scan_python_file
from .score import calculate_score
```

2. **Modify `scan_skill()` in scanner.py or cli.py to use AST for .py files:**
   - If file ends with `.py`, try `scan_python_file()` first
   - If it returns results or succeeds, use those
   - Combine with regex results for non-Python files

3. **Add score display after findings table:**

```python
score_result = calculate_score(findings)

# Color-coded grade
grade_colors = {'A': 'green', 'B': 'blue', 'C': 'yellow', 'D': 'orange1', 'F': 'red'}
grade = score_result['grade']

console.print(f"\n[bold]Security Score: {score_result['score']}/100[/bold] ", end='')
console.print(f"[{grade_colors[grade]}]Grade: {grade}[/]")

# Breakdown
if score_result['score'] < 100:
    console.print("\n[dim]Score Breakdown:[/dim]")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        data = score_result['breakdown'][sev]
        if data['count'] > 0:
            console.print(f"  -{data['deduction']:2d} pts: {data['count']}x {sev}")
```

---

## Testing

After implementation, this command should work:

```bash
cd /home/ubuntu/clawd/tools/skill-audit
uv run skill-audit ./test-vulnerable
```

Create a test file at `test-vulnerable/vuln.py`:

```python
import os
import subprocess
import pickle

def bad_stuff(user_input):
    eval(user_input)
    exec(user_input)
    os.system(f"echo {user_input}")
    subprocess.run(user_input, shell=True)
    pickle.loads(user_input)
```

Expected output should show:
- 3 CRITICAL findings (eval, exec, subprocess with shell=True)
- 2 HIGH findings (os.system, pickle.loads)
- Security Score around 25-35/100, Grade F

---

## Constraints

- Use only standard library + existing dependencies (click, rich)
- Maintain existing return format for findings (dict with severity, type, file, line, description)
- Handle file read errors gracefully
- Handle Python syntax errors gracefully (fall back to regex)

---

## Definition of Done

- [ ] `ast_scanner.py` detects all dangerous patterns listed above
- [ ] `score.py` calculates score with capped deductions
- [ ] CLI displays score and grade with color
- [ ] Existing regex scanning still works for non-Python files
- [ ] Test file produces expected output
