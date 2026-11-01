"""
Password Strength Analyzer
===========================
Evaluates password strength via:
  - Length assessment
  - Entropy calculation (character diversity)
  - Rule-based scoring
  - Weak/leaked password detection
  - Actionable suggestions + alternative generation
"""

import sys
import io
# Force UTF-8 output on Windows (fixes UnicodeEncodeError with box-drawing / emoji chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import math
import re
import os
import secrets
import string
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

# ─── ANSI Colours (disabled gracefully on Windows without VT support) ─────────
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )
except Exception:
    pass

RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class PasswordReport:
    password: str
    length: int
    entropy: float
    score: int                        # 0-100
    grade: str                        # F / D / C / B / A / A+
    strength_label: str               # Very Weak … Very Strong
    color: str
    checks: dict[str, bool]
    issues: list[str]
    suggestions: list[str]
    alternatives: list[str] = field(default_factory=list)
    is_common: bool = False


# ─── Weak Password Database ───────────────────────────────────────────────────

def load_weak_passwords(path: str = "weak_passwords.txt") -> set[str]:
    """Load known weak / leaked passwords from a flat text file."""
    db_path = Path(path)
    if not db_path.exists():
        # Try relative to this script's directory
        db_path = Path(__file__).parent / path
    if db_path.exists():
        return {line.strip().lower() for line in db_path.read_text().splitlines() if line.strip()}
    return set()


WEAK_PASSWORDS: set[str] = load_weak_passwords()


# ─── Core Analysis Functions ──────────────────────────────────────────────────

def calculate_charset_size(password: str) -> int:
    """Return the character-set pool size used in the password."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password):
        pool += 32
    if re.search(r"[^\x00-\x7F]", password):   # unicode / emoji
        pool += 40
    return max(pool, 1)


def calculate_entropy(password: str) -> float:
    """
    Shannon-inspired brute-force entropy:
        H = L × log2(N)
    where L = length, N = character pool size.
    """
    N = calculate_charset_size(password)
    L = len(password)
    return round(L * math.log2(N), 2)


def run_checks(password: str) -> dict[str, bool]:
    """Run all rule-based checks; return a dict of {check_name: passed}."""
    return {
        "min_length_8":      len(password) >= 8,
        "min_length_12":     len(password) >= 12,
        "has_lowercase":     bool(re.search(r"[a-z]", password)),
        "has_uppercase":     bool(re.search(r"[A-Z]", password)),
        "has_digit":         bool(re.search(r"\d", password)),
        "has_special":       bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password)),
        "no_repeating_chars": not bool(re.search(r"(.)\1{2,}", password)),
        "no_sequential":     not bool(re.search(
            r"(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|"
            r"ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|"
            r"vwx|wxy|xyz|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|"
            r"ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)", password.lower()
        )),
        "no_common_patterns": not bool(re.search(
            r"(?i)(password|pass|pwd|letmein|admin|login|welcome|monkey|dragon|"
            r"sunshine|princess|iloveyou|master|qwerty|azerty|dvorak)", password
        )),
        "not_all_same_char":  len(set(password)) > 1,
    }


def score_password(checks: dict[str, bool], entropy: float, password: str) -> int:
    """
    Produce a 0-100 score from entropy + rule bonuses/penalties.
    """
    score = 0

    # ── Entropy band (max 50 pts) ──────────────────────────────────────────
    if entropy >= 128:
        score += 50
    elif entropy >= 80:
        score += 40
    elif entropy >= 60:
        score += 30
    elif entropy >= 40:
        score += 20
    elif entropy >= 25:
        score += 10
    elif entropy >= 15:
        score += 5

    # ── Rule bonuses (max 50 pts) ──────────────────────────────────────────
    rule_weights = {
        "min_length_8":       5,
        "min_length_12":      10,
        "has_lowercase":      5,
        "has_uppercase":      8,
        "has_digit":          8,
        "has_special":        12,
        "no_repeating_chars": 4,
        "no_sequential":      4,
        "no_common_patterns": 4,
        "not_all_same_char":  0,   # sanity check, no extra pts
    }
    for check, passed in checks.items():
        if passed:
            score += rule_weights.get(check, 0)

    # ── Penalties ──────────────────────────────────────────────────────────
    if password.lower() in WEAK_PASSWORDS:
        score = max(score - 40, 0)
    if len(password) < 6:
        score = max(score - 20, 0)

    return min(score, 100)


def grade_and_label(score: int) -> tuple[str, str, str]:
    """Return (grade, strength_label, ansi_color) from score."""
    if score >= 90:
        return "A+", "Very Strong", GREEN
    elif score >= 75:
        return "A",  "Strong",      GREEN
    elif score >= 55:
        return "B",  "Moderate",    YELLOW
    elif score >= 35:
        return "C",  "Weak",        YELLOW
    elif score >= 15:
        return "D",  "Very Weak",   RED
    else:
        return "F",  "Critically Weak", RED


def collect_issues_and_suggestions(
    checks: dict[str, bool],
    password: str,
    entropy: float,
    is_common: bool,
) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    suggestions: list[str] = []

    if is_common:
        issues.append("This password appears in known leaked-password lists.")
        suggestions.append("Choose a unique password that is not a dictionary word or common phrase.")

    if not checks["min_length_8"]:
        issues.append(f"Too short ({len(password)} chars). Minimum is 8.")
        suggestions.append("Aim for at least 12 characters.")
    elif not checks["min_length_12"]:
        suggestions.append("Increase length to 12+ characters for stronger entropy.")

    if not checks["has_lowercase"]:
        issues.append("No lowercase letters detected.")
        suggestions.append("Mix lowercase letters (a–z).")

    if not checks["has_uppercase"]:
        issues.append("No uppercase letters detected.")
        suggestions.append("Add uppercase letters (A–Z).")

    if not checks["has_digit"]:
        issues.append("No digits detected.")
        suggestions.append("Include at least one digit (0–9).")

    if not checks["has_special"]:
        issues.append("No special characters detected.")
        suggestions.append("Add special characters like !@#$%^&*.")

    if not checks["no_repeating_chars"]:
        issues.append("Contains repeating character sequences (e.g. 'aaa').")
        suggestions.append("Avoid three or more consecutive identical characters.")

    if not checks["no_sequential"]:
        issues.append("Contains sequential patterns (e.g. '123', 'abc', 'qwe').")
        suggestions.append("Remove keyboard walks and number sequences.")

    if not checks["no_common_patterns"]:
        issues.append("Contains a commonly used word or pattern (e.g. 'password', 'admin').")
        suggestions.append("Replace common words with random or mnemonic substitutes.")

    if not checks["not_all_same_char"]:
        issues.append("All characters are identical!")
        suggestions.append("Use a diverse mix of characters.")

    if entropy < 40 and not issues:
        issues.append(f"Low entropy ({entropy} bits). Easy to brute-force.")
        suggestions.append("Increase character variety and length.")

    if not suggestions:
        suggestions.append("Great password! Make sure to store it in a password manager.")

    return issues, suggestions


# ─── Alternative Password Generator ──────────────────────────────────────────

def generate_alternatives(n: int = 3) -> list[str]:
    """Generate n strong random passwords of varying styles."""
    alts: list[str] = []

    # Style 1: Random 16-char alphanumeric + special
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    alts.append("".join(secrets.choice(alphabet) for _ in range(16)))

    # Style 2: Passphrase (4 random words from a small list)
    word_pool = [
        "tiger", "river", "cloud", "stone", "flame", "earth",
        "swift", "brave", "lucky", "prime", "vivid", "noble",
        "pixel", "quark", "sonic", "frost", "cyber", "lunar",
    ]
    sep = secrets.choice(["-", "_", ".", "~"])
    words = [secrets.choice(word_pool).capitalize() for _ in range(4)]
    digit_suffix = str(secrets.randbelow(9000) + 1000)
    alts.append(sep.join(words) + sep + digit_suffix)

    # Style 3: Mixed with guaranteed complexity
    chars = (
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%^&*")
        + "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(12))
    )
    shuffled = list(chars)
    # Fisher-Yates shuffle using secrets
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    alts.append("".join(shuffled))

    return alts[:n]


# ─── Main Analyzer ────────────────────────────────────────────────────────────

def analyze_password(password: str) -> PasswordReport:
    length    = len(password)
    entropy   = calculate_entropy(password)
    checks    = run_checks(password)
    is_common = password.lower() in WEAK_PASSWORDS
    score     = score_password(checks, entropy, password)
    grade, label, color = grade_and_label(score)
    issues, suggestions  = collect_issues_and_suggestions(checks, password, entropy, is_common)
    alternatives = generate_alternatives(3)

    return PasswordReport(
        password=password,
        length=length,
        entropy=entropy,
        score=score,
        grade=grade,
        strength_label=label,
        color=color,
        checks=checks,
        issues=issues,
        suggestions=suggestions,
        alternatives=alternatives,
        is_common=is_common,
    )


# ─── CLI Display ──────────────────────────────────────────────────────────────

def render_bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    return f"[{bar}]"


def print_report(report: PasswordReport) -> None:
    c   = report.color
    sep = BOLD + CYAN + "─" * 52 + RESET

    print(f"\n{sep}")
    print(f"  {BOLD}{CYAN}🔐 PASSWORD STRENGTH REPORT{RESET}")
    print(sep)

    # Strength bar
    bar = render_bar(report.score)
    print(f"\n  {BOLD}Strength:{RESET} {c}{report.strength_label}  {bar}  {report.score}/100  [{report.grade}]{RESET}")

    # Metrics table
    print(f"\n  {BOLD}📏 Length  :{RESET} {report.length} characters")
    print(f"  {BOLD}🔢 Entropy :{RESET} {report.entropy} bits")
    entropy_note = (
        "Very Low – trivial to crack"   if report.entropy < 25 else
        "Low – crackable quickly"        if report.entropy < 40 else
        "Moderate – reasonable security" if report.entropy < 60 else
        "High – brute-force resistant"   if report.entropy < 80 else
        "Very High – excellent security"
    )
    print(f"             {CYAN}({entropy_note}){RESET}")

    # Check-list
    print(f"\n  {BOLD}✅ Rule Checks:{RESET}")
    check_labels = {
        "min_length_8":       "At least 8 characters",
        "min_length_12":      "At least 12 characters",
        "has_lowercase":      "Lowercase letters (a-z)",
        "has_uppercase":      "Uppercase letters (A-Z)",
        "has_digit":          "Digits (0-9)",
        "has_special":        "Special characters (!@#…)",
        "no_repeating_chars": "No repeating chars (aaa)",
        "no_sequential":      "No sequential patterns (123, abc)",
        "no_common_patterns": "No common words (password, admin)",
        "not_all_same_char":  "Diverse character set",
    }
    for key, label in check_labels.items():
        icon = f"{GREEN}✓{RESET}" if report.checks[key] else f"{RED}✗{RESET}"
        print(f"    {icon}  {label}")

    # Common password warning
    if report.is_common:
        print(f"\n  {RED}{BOLD}⚠  COMPROMISED: This password is in a known leaked-password list!{RESET}")

    # Issues
    if report.issues:
        print(f"\n  {BOLD}{RED}❌ Issues Found:{RESET}")
        for issue in report.issues:
            print(f"    • {issue}")

    # Suggestions
    print(f"\n  {BOLD}{YELLOW}💡 Suggestions:{RESET}")
    for tip in report.suggestions:
        print(f"    → {tip}")

    # Alternatives
    print(f"\n  {BOLD}🎲 Suggested Strong Alternatives:{RESET}")
    for i, alt in enumerate(report.alternatives, 1):
        print(f"    {i}. {GREEN}{alt}{RESET}")

    print(f"\n{sep}\n")


# ─── Interactive CLI Loop ─────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════╗")
    print(f"║   🔒 Password Strength Analyzer      ║")
    print(f"║   Type 'quit' or 'q' to exit          ║")
    print(f"╚══════════════════════════════════════╝{RESET}\n")

    if WEAK_PASSWORDS:
        print(f"  {CYAN}Loaded {len(WEAK_PASSWORDS)} known weak passwords for comparison.{RESET}")
    else:
        print(f"  {YELLOW}Weak password list not found – common-password check disabled.{RESET}")

    while True:
        try:
            password = input(f"\n{BOLD}Enter a password to analyze: {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{CYAN}Goodbye!{RESET}")
            break

        if password.lower() in {"quit", "q", "exit"}:
            print(f"\n{CYAN}Goodbye!{RESET}")
            break

        if not password:
            print(f"  {YELLOW}Please enter a password.{RESET}")
            continue

        report = analyze_password(password)
        print_report(report)


if __name__ == "__main__":
    main()
