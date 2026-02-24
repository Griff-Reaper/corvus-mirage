"""
Corvus Mirage — Red Team Simulator
===================================
Run the full simulation with one command:

    python main.py

Optional flags:
    --category "Prompt Injection"   # Run only one category
    --vector gateway                # Run only gateway or aria attacks
    --no-save                       # Don't write report files
    --quiet                         # Suppress per-attack output
    --dry-run                       # Print attack list without firing

Output:
    - Live per-attack results to stdout
    - Clean coverage table at the end
    - JSON report saved to reports/
    - Human-readable summary saved to reports/
"""

import asyncio
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.attack_library import (
    ALL_ATTACKS,
    AttackCategory,
    AttackVector,
    summary as library_summary,
)
from core.attack_runner import AttackRunner
from core.scorer import score_results, generate_json_report, generate_text_report, print_live_summary
from config import config


def parse_args():
    parser = argparse.ArgumentParser(
        description="Corvus Mirage Red Team Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Full simulation
  python main.py --category "Jailbreak"      # Only jailbreak attacks
  python main.py --vector aria               # Only vishing attacks
  python main.py --dry-run                   # Preview attacks without firing
  python main.py --quiet --no-save           # Silent mode, no files
        """,
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Filter to a single attack category (e.g. 'Prompt Injection', 'Jailbreak')",
    )
    parser.add_argument(
        "--vector",
        type=str,
        default=None,
        choices=["gateway", "aria", "both"],
        help="Filter to attacks targeting a specific vector",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save report files",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-attack output (still shows final table)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List attacks that would be fired without actually sending them",
    )
    return parser.parse_args()


def filter_attacks(args):
    attacks = ALL_ATTACKS

    if args.category:
        # Case-insensitive match
        target = args.category.lower()
        attacks = [
            a for a in attacks
            if a.category.value.lower() == target
        ]
        if not attacks:
            valid = [c.value for c in AttackCategory]
            print(f"❌ Unknown category '{args.category}'. Valid: {valid}")
            sys.exit(1)

    if args.vector:
        vector_map = {
            "gateway": AttackVector.GATEWAY,
            "aria": AttackVector.ARIA,
            "both": AttackVector.BOTH,
        }
        v = vector_map[args.vector]
        attacks = [a for a in attacks if a.vector in (v, AttackVector.BOTH)]

    return attacks


def print_banner():
    print("""
   ██████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
  ██║     ██║   ██║██████╔╝██║   ██║███████╗
  ██║     ██║   ██║██╔══██╗╚██╗ ██╔╝╚════██║
  ╚██████╗╚██████╔╝██║  ██║ ╚████╔╝ ███████║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝
            MIRAGE — Red Team Simulator
    """)


async def main():
    args = parse_args()
    print_banner()

    attacks = filter_attacks(args)

    # Library summary
    lib = library_summary()
    print(f"  Attack Library: {lib['total']} attacks across {len(lib['by_category'])} categories")
    print(f"  Running:        {len(attacks)} attacks")
    print(f"  Gateway:        {config.gateway_api}")
    print(f"  ARIA:           {config.aria_api}")
    print()

    # Dry run — just list attacks
    if args.dry_run:
        print("DRY RUN — these attacks would be fired:\n")
        for a in attacks:
            print(f"  [{a.id}] {a.category.value:<22} {a.vector.value:<10} [{a.severity.value.upper():8s}] {a.description}")
        print(f"\nTotal: {len(attacks)} attacks")
        return

    # Run simulation
    runner = AttackRunner(verbose=not args.quiet)
    results = await runner.run(attacks)

    if not results:
        print("No results — check that your services are running.")
        sys.exit(1)

    # Score
    score_data = score_results(results)

    # Print live summary table
    print_live_summary(score_data)

    # Save reports
    if not args.no_save:
        json_path = generate_json_report(score_data)
        txt_path, _ = generate_text_report(score_data)
        print(f"  📄 JSON report: {json_path}")
        print(f"  📋 Text report: {txt_path}")
        print()

    # Exit code — 0 if passing, 1 if not (useful for CI)
    if not score_data["summary"]["pitch_ready"]:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
