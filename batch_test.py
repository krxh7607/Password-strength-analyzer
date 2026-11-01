"""
batch_test.py  –  Non-interactive demo of the Password Strength Analyzer

Run:
    python batch_test.py
"""

from password_analyzer import analyze_password, print_report, GREEN, CYAN, BOLD, RESET

DEMO_PASSWORDS = [
    "123456",           # critically weak / common
    "password",         # common word
    "hello",            # very short
    "abc123",           # short + common
    "Winter2024!",      # moderate
    "Tr0ub4dor&3",      # good (XKCD-style)
    "MyS3cur3P@ss!",    # strong
    "correct-horse-battery-staple",  # long passphrase
    "X#9mK!qR2@nW7$vL",             # very strong random
    "aaaaaaaaa",        # all same char
    "qwertyuiop",       # keyboard walk
]

def main():
    print(f"\n{BOLD}{CYAN}{'═'*52}")
    print(f"   🧪  BATCH PASSWORD ANALYSIS DEMO")
    print(f"{'═'*52}{RESET}\n")

    for pwd in DEMO_PASSWORDS:
        masked = pwd[:2] + "•" * max(len(pwd)-4, 1) + pwd[-2:]
        print(f"{BOLD}Testing: {CYAN}{masked}{RESET}")
        report = analyze_password(pwd)
        print_report(report)
        input("  Press Enter for next password…\n")

    print(f"{GREEN}{BOLD}All tests complete.{RESET}\n")

if __name__ == "__main__":
    main()
