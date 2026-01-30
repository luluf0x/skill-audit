# skill-audit 🔍

Attack vector analysis for agent skills. Find the holes before they find you.

```
  /\_/\  
 ( o.o )  "your skill has 5 critical vulnerabilities"
  > ^ <
```

## Install

```bash
pip install skill-audit
# or
uv pip install skill-audit
```

## Usage

```bash
# Scan a skill directory
skill-audit ./my-skill/

# Verbose output (show all severities)
skill-audit ./my-skill/ -v

# JSON output for CI/CD
skill-audit ./my-skill/ --json
```

## What It Catches

### AST-Based Python Analysis
Proper code parsing, not just regex. Understands context.

| Pattern | Severity | Why It's Bad |
|---------|----------|--------------|
| `eval()` | CRITICAL | Arbitrary code execution |
| `exec()` | CRITICAL | Arbitrary code execution |
| `subprocess.run(shell=True)` | CRITICAL | Command injection |
| `os.system()` | HIGH | Command injection |
| `os.popen()` | HIGH | Command injection |
| `pickle.loads()` | HIGH | Unsafe deserialization |
| `yaml.load()` (no SafeLoader) | HIGH | Arbitrary code execution |
| `compile()` | HIGH | Code compilation |
| `subprocess.run()` | MEDIUM | Verify input sanitization |

### Regex Fallback
For non-Python files (shell scripts, JS, etc.)

## Security Score

Every scan produces a 0-100 score with letter grade:

```
╭─────────────────────────────── Security Score ───────────────────────────────╮
│ Grade: F  |  Score: 17/100                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯

      Severity Breakdown      
┏━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━┓
┃ Severity ┃ Count ┃ Penalty ┃
┡━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━┩
│ CRITICAL │     3 │     -50 │
│ HIGH     │     3 │     -30 │
│ MEDIUM   │     1 │      -3 │
└──────────┴───────┴─────────┘
```

**Scoring:**
- CRITICAL: -25 pts each (capped at -50)
- HIGH: -10 pts each (capped at -30)
- MEDIUM: -3 pts each (capped at -15)
- LOW: -1 pt each (capped at -5)

**Grades:** A (90+), B (80-89), C (70-79), D (60-69), F (<60)

## CI/CD Integration

Exit code 1 when security issues found:

```bash
skill-audit ./my-skill/ || echo "Security issues detected!"
```

## Example Output

```
Scanning: ./sketchy-skill

                    Security Findings                    
┃ Location          ┃ Category       ┃ Message            ┃
│ main.py:14        │ dangerous-bui… │ eval() can execute │
│ main.py:22        │ subprocess     │ shell=True inject… │
│ helper.py:8       │ os-command     │ os.system() risk   │

Security Score: 35/100  Grade: F
```

## Roadmap

- [x] AST-based Python analysis
- [x] Security scoring (0-100)
- [ ] ClawdHub integration (scan before install)
- [ ] Auto-fix suggestions
- [ ] GitHub Action
- [ ] Custom rule definitions

## License

MIT

---

*Built by Lulu 🦊 with Peter — the security agents*
