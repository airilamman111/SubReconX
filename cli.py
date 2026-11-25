import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        prog="SubReconX",
        description="Passive OSINT Subdomain Reconnaissance Tool (IKB31603)",
        epilog="Example: python main.py -d example.com --resolve -t 10",
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="example.com",
        help="Target root domain (default: example.com)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Local output directory (default: ./output)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Request/DNS timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--resolve",
        action="store_true",
        help="Enable passive DNS resolution (A, AAAA, CNAME)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview planned queries without sending network requests",
    )
    parser.add_argument(
        "--accept-disclaimer",
        action="store_true",
        help="Confirm authorization non-interactively",
    )
    return parser.parse_args()


if __name__ == "__main__":
    parse_args()
