# Password Strength Analyzer

A Python CLI tool to evaluate password strength using **length**, **entropy**, and **rule-based scoring**, with weak password detection and alternative suggestions.

## Project Structure

```
password-strength-analyzer/
├── password_analyzer.py   # Core engine + interactive CLI
├── batch_test.py          # Demo runner (no interaction required)
└── weak_passwords.txt     # Known weak/leaked passwords list
```

## Quick Start

```bash
# Interactive mode — enter passwords one at a time
python -X utf8 password_analyzer.py

# Batch demo — steps through representative passwords
python -X utf8 batch_test.py
```

No external dependencies — uses Python stdlib only (`math`, `re`, `os`, `secrets`, `string`).

---

## How It Works

### 1 — Length Assessment
Reports exact character count and flags passwords under 8 and 12 characters with penalties.

### 2 — Entropy Calculation
Uses the brute-force entropy formula:

```
H = L × log₂(N)
```

| Variable | Meaning |
|---|---|
| `L` | Password length |
| `N` | Character pool size (26 lower + 26 upper + 10 digits + 32 specials = up to 94) |
| `H` | Bits of entropy |

| Entropy (bits) | Security level |
|---|---|
| < 25 | Trivial to crack |
| 25–40 | Low – crackable quickly |
| 40–60 | Moderate – reasonable |
| 60–80 | High – brute-force resistant |
| ≥ 80 | Very High – excellent |

### 3 — Rule-Based Scoring (0–100)

| Category | Points |
|---|---|
| Entropy band | 0–50 |
| ≥ 8 chars | +5 |
| ≥ 12 chars | +10 |
| Has lowercase | +5 |
| Has uppercase | +8 |
| Has digit | +8 |
| Has special char | +12 |
| No repeating chars | +4 |
| No sequential patterns | +4 |
| No common word patterns | +4 |
| Known weak password | −40 |
| Length < 6 | −20 |

| Score | Grade | Label |
|---|---|---|
| 90–100 | A+ | Very Strong |
| 75–89 | A | Strong |
| 55–74 | B | Moderate |
| 35–54 | C | Weak |
| 15–34 | D | Very Weak |
| 0–14 | F | Critically Weak |

### 4 — Weak Password Detection
Compares against `weak_passwords.txt` (a curated list of 70+ leaked/common passwords). Match → −40 point penalty + warning banner.

### 5 — Password Suggestions & Alternatives
Generates 3 strong alternatives:
- **Random**: 16-char alphanumeric + special
- **Passphrase**: 4 capitalized words + separator + 4-digit suffix
- **Mixed**: Guaranteed uppercase + lowercase + digit + special, shuffled securely

---

## Example Output

```
  Strength: Very Strong  [████████████████████████████░░]  91/100  [A+]

  📏 Length  : 16 characters
  🔢 Entropy : 104.8 bits
             (Very High – excellent security)

  ✅ Rule Checks:
    ✓  At least 8 characters
    ✓  At least 12 characters
    ✓  Lowercase letters (a-z)
    ✓  Uppercase letters (A-Z)
    ✓  Digits (0-9)
    ✓  Special characters (!@#…)
    ✓  No repeating chars (aaa)
    ✓  No sequential patterns (123, abc)
    ✓  No common words (password, admin)
    ✓  Diverse character set

  💡 Suggestions:
    → Great password! Make sure to store it in a password manager.

  🎲 Suggested Strong Alternatives:
    1. kR#7mP!qNv$2xWjY
    2. Swift~Pixel~Lunar~Noble~4829
    3. M3@kXvpQn!Rj8Zsd
```
