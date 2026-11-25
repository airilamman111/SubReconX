import re
import sys

SAFE_LOCAL_TARGETS = {"127.0.0.1", "localhost"}
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$"
)


def enforce_legal_disclaimer(auto_accept=False):
    banner = """
====================================================================
[!] LEGAL DISCLAIMER & AUTHORIZATION WARNING - SubReconX
====================================================================
This tool performs passive OSINT reconnaissance for educational and
authorized security assessment purposes only.

Under the Malaysia Computer Crimes Act 1997 (Act 563), unauthorized
access, interception, or misuse of computer systems and network data
is a criminal offense punishable by fine and/or imprisonment.

By proceeding, you confirm that you have explicit written
authorization to assess the specified target scope.
====================================================================
"""
    print(banner)
    if auto_accept:
        print("[*] Authorization confirmed via --accept-disclaimer flag.\n")
        return True

    choice = input("Do you have explicit authorization to scan this target? (y/N): ").strip().lower()
    if choice not in ("y", "yes"):
        print("[!] Authorization not confirmed. Aborting execution cleanly.")
        sys.exit(0)
    print("[*] Authorization confirmed. Proceeding...\n")
    return True


def validate_target_scope(target):
    cleaned = target.strip().lower()
    if "://" in cleaned or "/" in cleaned:
        raise ValueError(
            f"Out-of-scope or malformed target '{target}'. Provide a bare domain (e.g., example.com) or localhost."
        )
    if cleaned in SAFE_LOCAL_TARGETS:
        return cleaned, True
    if not DOMAIN_REGEX.match(cleaned):
        raise ValueError(
            f"Invalid target scope '{target}'. Must be a valid root domain (default: example.com)."
        )
    return cleaned, False


if __name__ == "__main__":
    for sample in ["example.com", "127.0.0.1", "https://evil.com/admin"]:
        try:
            valid, is_local = validate_target_scope(sample)
            print(f"[PASS] {sample} -> valid={valid}, safe_local={is_local}")
        except ValueError as err:
            print(f"[BLOCKED] {sample} -> {err}")