"""
Red Team Simulator — Scorer & Report Generator
Aggregates attack results into a detection coverage score per category
and produces both a structured JSON report and a human-readable summary.

This is the number that makes Corvus Mirage a credible enterprise pitch.
"""

import json
import os
import sys
from datetime import datetime
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config
from core.attack_library import AttackCategory
from core.attack_runner import AttackResult, DetectionResult


# ─────────────────────────────────────────────────────────────
# SCORING ENGINE
# ─────────────────────────────────────────────────────────────

def score_results(results: List[AttackResult]) -> dict:
    """
    Aggregate results into a full coverage report.
    Returns a nested dict with per-category and overall scores.
    """
    if not results:
        return {}

    # Filter out ERRORs for scoring (can't score unreachable endpoints)
    scoreable = [r for r in results if r.result != DetectionResult.ERROR]
    errors = [r for r in results if r.result == DetectionResult.ERROR]

    # Per-category breakdown
    categories = {}
    for category in AttackCategory:
        cat_results = [r for r in scoreable if r.attack.category == category]
        if not cat_results:
            continue

        detected = sum(1 for r in cat_results if r.caught)
        total = len(cat_results)
        pct = detected / total if total > 0 else 0.0

        # Severity-weighted score (critical misses hurt more)
        severity_weights = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        weighted_caught = sum(
            severity_weights.get(r.attack.severity.value, 1)
            for r in cat_results if r.caught
        )
        weighted_total = sum(
            severity_weights.get(r.attack.severity.value, 1)
            for r in cat_results
        )
        weighted_pct = weighted_caught / weighted_total if weighted_total > 0 else 0.0

        missed = [
            {
                "id": r.attack.id,
                "severity": r.attack.severity.value,
                "description": r.attack.description,
                "notes": r.notes,
            }
            for r in cat_results
            if not r.caught
        ]

        categories[category.value] = {
            "detected": detected,
            "total": total,
            "coverage_pct": round(pct * 100, 1),
            "weighted_coverage_pct": round(weighted_pct * 100, 1),
            "passing": pct >= config.detection_pass_threshold,
            "missed_attacks": missed,
            "avg_response_ms": round(
                sum(r.response_time_ms for r in cat_results) / len(cat_results), 1
            ),
        }

    # Overall score
    total_caught = sum(1 for r in scoreable if r.caught)
    total_attacks = len(scoreable)
    overall_pct = total_caught / total_attacks if total_attacks > 0 else 0.0

    # Severity-weighted overall
    severity_weights = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    w_caught = sum(severity_weights.get(r.attack.severity.value, 1) for r in scoreable if r.caught)
    w_total = sum(severity_weights.get(r.attack.severity.value, 1) for r in scoreable)
    weighted_overall = w_caught / w_total if w_total > 0 else 0.0

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "platform": "Corvus Mirage Red Team Simulator",
        "version": "1.0.0",
        "summary": {
            "total_attacks": len(results),
            "scoreable_attacks": total_attacks,
            "errors_skipped": len(errors),
            "total_caught": total_caught,
            "overall_coverage_pct": round(overall_pct * 100, 1),
            "weighted_coverage_pct": round(weighted_overall * 100, 1),
            "overall_passing": overall_pct >= config.overall_pass_threshold,
            "pitch_ready": overall_pct >= config.overall_pass_threshold,
        },
        "categories": categories,
        "errors": [
            {
                "attack_id": r.attack.id,
                "category": r.attack.category.value,
                "notes": r.notes,
            }
            for r in errors
        ],
    }


# ─────────────────────────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────────────────────────

def generate_json_report(score_data: dict, output_dir: str = None) -> str:
    """Write the full JSON report to disk and return the file path."""
    if output_dir is None:
        output_dir = config.reports_dir
    os.makedirs(output_dir, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"corvus_redteam_report_{ts}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(score_data, f, indent=2)

    return filepath


def generate_text_report(score_data: dict, output_dir: str = None) -> str:
    """
    Generate the human-readable summary report.
    This is the format you show in the pitch.
    Returns the file path.
    """
    if not score_data:
        return ""

    if output_dir is None:
        output_dir = config.reports_dir
    os.makedirs(output_dir, exist_ok=True)

    summary = score_data["summary"]
    categories = score_data["categories"]
    ts = score_data["generated_at"]

    lines = []
    lines.append("=" * 60)
    lines.append("  CORVUS MIRAGE — RED TEAM SIMULATION REPORT")
    lines.append("=" * 60)
    lines.append(f"  Generated: {ts}")
    lines.append(f"  Platform:  {score_data['platform']}")
    lines.append("")

    # Per-category table
    lines.append("  DETECTION COVERAGE BY CATEGORY")
    lines.append("  " + "-" * 54)
    lines.append(f"  {'Category':<22} {'Caught':>8} {'Coverage':>10} {'Status':>8}")
    lines.append("  " + "-" * 54)

    for cat_name, cat_data in categories.items():
        caught = cat_data["detected"]
        total = cat_data["total"]
        pct = cat_data["coverage_pct"]
        passing = "✅ PASS" if cat_data["passing"] else "❌ FAIL"
        lines.append(
            f"  {cat_name:<22} {caught:>3}/{total:<4}  {pct:>6.1f}%   {passing}"
        )

    lines.append("  " + "-" * 54)

    # Overall
    overall_caught = summary["total_caught"]
    overall_total = summary["scoreable_attacks"]
    overall_pct = summary["overall_coverage_pct"]
    pitch_ready = summary["pitch_ready"]

    lines.append(
        f"  {'OVERALL COVERAGE':<22} {overall_caught:>3}/{overall_total:<4}  {overall_pct:>6.1f}%   "
        f"{'🚀 PITCH READY' if pitch_ready else '⚠️  NEEDS WORK'}"
    )
    lines.append("=" * 60)
    lines.append("")

    # Weighted score note
    w_pct = summary["weighted_coverage_pct"]
    lines.append(f"  Severity-weighted coverage: {w_pct:.1f}%")
    lines.append(f"  (Critical/high threats count more toward this score)")
    lines.append("")

    # Missed attacks by severity
    all_missed = []
    for cat_name, cat_data in categories.items():
        for m in cat_data.get("missed_attacks", []):
            m["category"] = cat_name
            all_missed.append(m)

    if all_missed:
        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_missed.sort(key=lambda x: sev_order.get(x["severity"], 4))

        lines.append(f"  MISSED ATTACKS ({len(all_missed)} total)")
        lines.append("  " + "-" * 54)
        for m in all_missed[:10]:  # Show top 10 in text report
            lines.append(
                f"  [{m['severity'].upper():8s}] [{m['id']}] {m['description'][:42]}"
            )
        if len(all_missed) > 10:
            lines.append(f"  ... and {len(all_missed) - 10} more (see JSON report)")
        lines.append("")

    # Error summary
    if score_data.get("errors"):
        lines.append(f"  ERRORS ({len(score_data['errors'])} — excluded from scoring)")
        lines.append("  " + "-" * 54)
        for e in score_data["errors"][:5]:
            lines.append(f"  [{e['attack_id']}] {e['notes'][:55]}")
        lines.append("")

    # Performance stats
    lines.append("  PERFORMANCE")
    lines.append("  " + "-" * 54)
    for cat_name, cat_data in categories.items():
        lines.append(
            f"  {cat_name:<30} avg {cat_data['avg_response_ms']:>6.0f}ms"
        )
    lines.append("")
    lines.append("=" * 60)
    lines.append("  The raven sees everything.")
    lines.append("=" * 60)

    report_text = "\n".join(lines)

    # Save
    ts_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"corvus_redteam_summary_{ts_str}.txt"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_text)

    return filepath, report_text


def print_live_summary(score_data: dict):
    """Print the clean coverage table to stdout — the pitch-ready output."""
    if not score_data:
        print("No results to display.")
        return

    summary = score_data["summary"]
    categories = score_data["categories"]

    print()
    print("=" * 55)
    print("  CORVUS MIRAGE — DETECTION COVERAGE")
    print("=" * 55)

    for cat_name, cat_data in categories.items():
        caught = cat_data["detected"]
        total = cat_data["total"]
        pct = cat_data["coverage_pct"]
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"  {cat_name:<22} {caught:>3}/{total:<3} ({pct:>5.1f}%)")

    print("  " + "-" * 49)
    overall_caught = summary["total_caught"]
    overall_total = summary["scoreable_attacks"]
    overall_pct = summary["overall_coverage_pct"]
    pitch_label = "🚀 PITCH READY" if summary["pitch_ready"] else "⚠️  NEEDS WORK"

    print(f"  {'Overall Coverage':<22} {overall_caught:>3}/{overall_total:<3} ({overall_pct:>5.1f}%)  {pitch_label}")
    print("=" * 55)

    if summary.get("errors_skipped", 0) > 0:
        print(f"\n  ⚠️  {summary['errors_skipped']} attacks skipped (endpoint errors)")

    print()

def save_to_db(
    score_data: dict,
    results: list,
    db_path: str,
    run_id: str = None,
    report_json_path: str = None,
    report_txt_path: str = None,
) -> str:
    """
    Persist a completed red team run to the shared threat_intel DB.
    Writes one row to red_team_runs + one row per attack to red_team_findings.
    Returns the run_id.

    Add this call at the end of main.py after generate_json_report()
    and generate_text_report():

        from core.db_writer import save_run, save_findings
        run_id = save_to_db(score_data, results, config.threat_intel_db_path,
                            report_json_path=json_path, report_txt_path=txt_path)
    """
    from core.db_writer import save_run, save_findings

    run_id = save_run(
        db_path=db_path,
        score_data=score_data,
        run_id=run_id,
        report_json_path=report_json_path,
        report_txt_path=report_txt_path,
    )
    save_findings(db_path=db_path, results=results, run_id=run_id)
    return run_id