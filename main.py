from datetime import datetime, timezone
import signal
import sys
from cli import parse_args
from guardrails import enforce_legal_disclaimer, validate_target_scope
from osint_engine import run_recon
from output_handler import save_local_results


def handle_kill_switch(signum, frame):
    print("\n[!] KILL SWITCH ACTIVATED (SIGINT). Aborting SubReconX immediately.")
    sys.exit(130)


def main():
    signal.signal(signal.SIGINT, handle_kill_switch)
    args = parse_args()

    try:
        target, is_local = validate_target_scope(args.domain)
    except ValueError as err:
        print(f"[!] Scope Validation Error: {err}")
        sys.exit(1)

    enforce_legal_disclaimer(auto_accept=args.accept_disclaimer)

    print(f"[*] Target Scope : {target}")
    print(f"[*] Dry-Run Mode : {args.dry_run}")
    print("[*] Press Ctrl+C at any time to trigger the emergency kill switch.\n")

    if is_local:
        recon_data = {
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "dry_run": args.dry_run,
            "subdomains": [{"hostname": target}],
            "errors": ["Safe loopback target selected; external CT/DNS queries skipped."],
        }
    else:
        recon_data = run_recon(
            domain=target,
            timeout=args.timeout,
            resolve=args.resolve,
            dry_run=args.dry_run,
        )

    json_path, txt_path = save_local_results(recon_data, output_dir=args.output)
    print(f"[+] Scan complete. Discovered {len(recon_data['subdomains'])} unique host(s).")
    print(f"[+] JSON saved locally : {json_path}")
    print(f"[+] TXT saved locally  : {txt_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user. Exiting cleanly.")
        sys.exit(130)