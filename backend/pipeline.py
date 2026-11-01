import argparse
import hashlib
import json
import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.detector import scan_file
from repair.repair_agent import (
    DEFAULT_ATTEMPT1_PROMPT,
    GROQ_MODEL,
    PROMPT_VERSIONS,
    PatchValidationError,
    append_repair_log,
    generate_functional_tests,
    generate_patch_with_metadata,
    save_patch,
)
from verification.verifier import (
    verify_patch,
    format_report_markdown,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
SAMPLES_DIR = PROJECT_ROOT / "samples"

MAX_REPAIR_ATTEMPTS = 2
REPAIR_PROVIDER = "groq"

SUCCESS_VERDICTS = {"REPAIR_SUCCESSFUL", "VERIFIED_SECURE"}

logger = logging.getLogger("securecodeagent.pipeline")


def _comparison(report):
    return (
        (report or {})
        .get("checks", {})
        .get("security_rescan", {})
        .get("comparison", {})
    )


def _attempt_metrics(report, metadata):
    comparison = _comparison(report)
    checks = (report or {}).get("checks", {})
    tests = checks.get("functional_tests", {})

    return {
        "prompt_version": metadata.get("prompt_version"),
        "latency_seconds": metadata.get("latency_seconds"),
        "token_usage": metadata.get("token_usage"),
        "api_calls": metadata.get("api_calls"),
        "format_retries": metadata.get("format_retries"),
        "patch_validation_passed": (
            (metadata.get("validation") or {}).get("passed")
        ),
        "syntax_passed": checks.get("syntax", {}).get("passed"),
        "original_count": comparison.get("original_count"),
        "resolved_count": comparison.get("resolved_count"),
        "unresolved_count": comparison.get("unresolved_count"),
        "new_issues_count": comparison.get("new_issues_count"),
        "functional_tests_status": tests.get("status"),
    }


def _verification_error_report(message, original_findings):
    return {
        "verdict": "VERIFICATION_ERROR",
        "summary": f"Verification could not be completed: {message}",
        "checks": {
            "syntax": {},
            "security_rescan": {
                "scan_status": "ERROR",
                "scan_error": message,
                "comparison": {
                    "resolved_findings": [],
                    "unresolved_findings": original_findings,
                    "new_findings": [],
                },
            },
            "functional_tests": {},
        },
    }


def run_feedback_pipeline(
    original_file,
    test_file=None,
    max_attempts=MAX_REPAIR_ATTEMPTS,
    allow_demo_fallback=False,
    prompt_version=None,
    generate_tests=True,
    pause_seconds=0,
):

    original_path = Path(original_file).resolve()

    test_path = (
        Path(test_file).resolve()
        if test_file
        else None
    )

    if not original_path.is_file():
        raise FileNotFoundError(
            f"Original source file not found: {original_path}"
        )

    if original_path.suffix.lower() != ".py":
        raise ValueError(
            "Only Python files are supported."
        )

    if test_path is not None and not test_path.is_file():
        raise FileNotFoundError(
            f"Test file not found: {test_path}"
        )

    if not 1 <= max_attempts <= MAX_REPAIR_ATTEMPTS:
        raise ValueError(
            f"Maximum repair attempts must be between 1 and "
            f"{MAX_REPAIR_ATTEMPTS}."
        )

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    run_id = uuid.uuid4().hex[:10]

    original_code = original_path.read_text(
        encoding="utf-8"
    )

    print("\n[1/4] Scanning original Python file...")

    baseline = scan_file(str(original_path))

    original_findings = baseline.get("findings", [])

    print(
        f"Detected {baseline.get('total_issues', 0)} "
        "security issue(s)."
    )

    history = []
    final_report = None
    final_patch = None
    current_source = original_code
    last_report = None
    repair_api_error = None

    if not original_findings:
        print("No findings detected; repair is not required.")
        return {
            "run_id": run_id,
            "final_verdict": "NO_FINDINGS",
            "final_patch": None,
            "attempts_used": 0,
            "fallback_used": False,
            "repair_source": REPAIR_PROVIDER,
            "prompt_version": None,
            "history": [],
            "verification_report": None,
            "generated_test_file": None,
            "generated_test_status": "NOT_GENERATED",
            "generated_test_error": None,
            "functional_tests_executed": False,
            "repair_api_error": None,
            "original_finding_count": 0,
        }

    print("\n[2/4] Starting Groq repair and verification...")

    for attempt in range(1, max_attempts + 1):

        if attempt > 1 and pause_seconds > 0:
            print(f"Waiting {pause_seconds}s to respect API rate limits...")
            time.sleep(pause_seconds)

        print(
            f"\nRepair attempt {attempt}/{max_attempts}"
        )

        patch_path = (
            REPORTS_DIR
            / f"feedback_patch_{run_id}_v{attempt}.py"
        )

        report_path = (
            REPORTS_DIR
            / f"feedback_report_{run_id}_v{attempt}.md"
        )

        try:

            if attempt == 1:
                patched_code, metadata = generate_patch_with_metadata(
                    current_source,
                    findings=original_findings,
                    attempt=1,
                    prompt_version=prompt_version
                )

            else:
                patched_code, metadata = generate_patch_with_metadata(
                    current_source,
                    findings=original_findings,
                    original_source=original_code,
                    verification_report=last_report,
                    attempt=2
                )

            save_patch(
                patched_code,
                patch_path,
                original_path=original_path
            )

        except Exception as exc:

            error_message = str(exc)
            repair_api_error = error_message

            rejected = isinstance(exc, PatchValidationError)

            history.append(
                {
                    "attempt": attempt,
                    "patch": None,
                    "report": None,
                    "verdict": (
                        "PATCH_REJECTED"
                        if rejected
                        else "REPAIR_API_ERROR"
                    ),
                    "source": REPAIR_PROVIDER,
                    "error": error_message,
                }
            )

            print(f"Groq repair failed: {error_message}")

            break

        applicable_test = (
            str(test_path)
            if test_path is not None
            else None
        )

        try:

            report = verify_patch(
                original_file=str(original_path),
                patched_file=str(patch_path),
                test_file=applicable_test,
                original_findings=original_findings,
            )

        except Exception as exc:

            error_message = str(exc)

            history.append(
                {
                    "attempt": attempt,
                    "patch": str(patch_path),
                    "report": None,
                    "verdict": "VERIFICATION_ERROR",
                    "source": REPAIR_PROVIDER,
                    "error": error_message,
                    "metrics": _attempt_metrics(None, metadata),
                }
            )

            print(f"Verification failed: {error_message}")

            final_patch = str(patch_path)
            current_source = patched_code
            last_report = _verification_error_report(
                error_message,
                original_findings
            )

            continue

        report_path.write_text(
            format_report_markdown(report),
            encoding="utf-8"
        )

        verdict = report.get("verdict", "UNKNOWN")
        metrics = _attempt_metrics(report, metadata)

        history.append(
            {
                "attempt": attempt,
                "patch": str(patch_path),
                "report": str(report_path),
                "verdict": verdict,
                "source": REPAIR_PROVIDER,
                "plan": metadata.get("plan"),
                "patch_validation": metadata.get("validation"),
                "metrics": metrics,
            }
        )

        append_repair_log({
            "event": "verification",
            "run_id": run_id,
            "attempt": attempt,
            "prompt_version": metadata.get("prompt_version"),
            "verdict": verdict,
            **{
                key: metrics[key]
                for key in (
                    "syntax_passed",
                    "original_count",
                    "resolved_count",
                    "unresolved_count",
                    "new_issues_count",
                    "functional_tests_status",
                )
            },
        })

        final_report = report
        final_patch = str(patch_path)
        last_report = report

        print(f"Verification verdict: {verdict}")

        if verdict in SUCCESS_VERDICTS:
            print("\nPatch passed the available verification checks.")
            break

        if attempt < max_attempts:
            print(
                "\nVerification issues found."
                "\nSending actual feedback to Groq..."
            )

            current_source = patched_code

    print(
        "\n[3/4] Generating candidate functional tests..."
    )

    generated_test_path = None
    generated_test_status = "NOT_GENERATED"
    generated_test_error = None

    if test_path is not None:

        generated_test_status = "USER_TEST_FILE_PROVIDED"

    elif generate_tests:

        try:

            if final_patch and Path(final_patch).is_file():
                test_source = Path(final_patch).read_text(
                    encoding="utf-8"
                )
            else:
                test_source = original_code

            generated_tests = generate_functional_tests(
                test_source
            )

            generated_test_path = (
                REPORTS_DIR
                / f"generated_tests_{run_id}.py"
            )

            generated_test_path.write_text(
                generated_tests.rstrip() + "\n",
                encoding="utf-8"
            )

            generated_test_status = "GENERATED_NOT_EXECUTED"

            print("Candidate functional tests generated.")

        except Exception as exc:

            generated_test_status = "GENERATION_FAILED"
            generated_test_error = str(exc)

            print(f"Functional test generation failed: {exc}")

    print("\n[4/4] Preparing final pipeline result...")

    attempts_used = sum(
        1
        for item in history
        if item.get("patch") is not None
    )

    if repair_api_error:
        final_verdict = history[-1]["verdict"]

    elif final_report is not None:
        final_verdict = final_report.get("verdict", "UNKNOWN")

    elif history:
        final_verdict = history[-1].get(
            "verdict",
            "VERIFICATION_FAILED"
        )

    else:
        final_verdict = "VERIFICATION_FAILED"

    prompt_used = next(
        (
            item["metrics"]["prompt_version"]
            for item in history
            if item.get("metrics")
        ),
        prompt_version or DEFAULT_ATTEMPT1_PROMPT
    )

    result = {
        "run_id": run_id,
        "final_verdict": final_verdict,
        "final_patch": final_patch,
        "attempts_used": attempts_used,
        "fallback_used": False,
        "repair_source": REPAIR_PROVIDER,
        "prompt_version": prompt_used,
        "history": history,
        "verification_report": final_report,
        "generated_test_file": (
            str(generated_test_path)
            if generated_test_path
            else None
        ),
        "generated_test_status": generated_test_status,
        "generated_test_error": generated_test_error,
        "functional_tests_executed": test_path is not None,
        "repair_api_error": repair_api_error,
        "original_finding_count": len(original_findings),
    }

    print(f"\nFinal verdict: {final_verdict}")
    print(f"Repair attempts used: {attempts_used}")
    print(f"Repair provider: {REPAIR_PROVIDER}")

    return result


def _sum_known(values):
    known = [v for v in values if v is not None]
    return (sum(known), len(known)) if known else (None, 0)


def evaluate_samples(
    samples_dir=None,
    prompt_version=None,
    max_attempts=MAX_REPAIR_ATTEMPTS,
    output_path=None,
    delay_seconds=0,
):

    samples_dir = Path(samples_dir or SAMPLES_DIR).resolve()

    if not samples_dir.is_dir():
        raise FileNotFoundError(
            f"Samples directory not found: {samples_dir}"
        )

    sample_files = sorted(samples_dir.glob("*.py"))

    if not sample_files:
        raise FileNotFoundError(
            f"No .py samples found in {samples_dir}"
        )

    version = prompt_version or DEFAULT_ATTEMPT1_PROMPT

    if version not in PROMPT_VERSIONS:
        raise ValueError(f"Unknown prompt version: {version}")

    rows = []

    for position, sample in enumerate(sample_files):

        if position > 0 and delay_seconds > 0:
            print(f"Waiting {delay_seconds}s to respect API rate limits...")
            time.sleep(delay_seconds)

        row = {
            "sample": sample.name,
            "sha256": hashlib.sha256(
                sample.read_bytes()
            ).hexdigest()[:16],
        }

        try:
            result = run_feedback_pipeline(
                sample,
                max_attempts=max_attempts,
                prompt_version=version,
                generate_tests=False,
                pause_seconds=delay_seconds,
            )

        except Exception as exc:
            row.update({"status": "ERROR", "error": str(exc)})
            rows.append(row)
            continue

        if result["final_verdict"] == "NO_FINDINGS":
            row.update({"status": "NO_FINDINGS"})
            rows.append(row)
            continue

        attempts = result["history"]

        verified = [
            item["attempt"]
            for item in attempts
            if item["verdict"] in SUCCESS_VERDICTS
        ]

        last_metrics = next(
            (
                item["metrics"]
                for item in reversed(attempts)
                if item.get("metrics")
            ),
            {}
        )

        row.update({
            "status": "COMPLETED",
            "final_verdict": result["final_verdict"],
            "original_findings": result["original_finding_count"],
            "attempts_used": result["attempts_used"],
            "first_attempt_verified": 1 in verified,
            "verified_within_attempts": bool(verified),
            "resolved_findings": last_metrics.get("resolved_count"),
            "unresolved_findings": last_metrics.get("unresolved_count"),
            "new_findings": last_metrics.get("new_issues_count"),
            "functional_tests_status": last_metrics.get(
                "functional_tests_status"
            ),
            "attempts": [
                {
                    "attempt": item["attempt"],
                    "verdict": item["verdict"],
                    **(item.get("metrics") or {}),
                }
                for item in attempts
            ],
            "generation_error": result["repair_api_error"],
        })

        rows.append(row)

    completed = [r for r in rows if r["status"] == "COMPLETED"]

    all_attempts = [
        a for r in completed for a in r["attempts"]
        if "syntax_passed" in a
    ]

    tokens, token_attempts = _sum_known(
        (a.get("token_usage") or {}).get("total_tokens")
        for a in all_attempts
    )

    latency, latency_attempts = _sum_known(
        a.get("latency_seconds") for a in all_attempts
    )

    resolved, _ = _sum_known(r["resolved_findings"] for r in completed)
    originals, _ = _sum_known(r["original_findings"] for r in completed)
    new_total, _ = _sum_known(r["new_findings"] for r in completed)

    test_status = {}

    for r in completed:
        key = r.get("functional_tests_status") or "NOT_RUN"
        test_status[key] = test_status.get(key, 0) + 1

    total = len(completed)

    summary = {
        "prompt_version_attempt_1": version,
        "model": GROQ_MODEL,
        "max_attempts": max_attempts,
        "samples_total": len(rows),
        "samples_evaluated": total,
        "samples_skipped_or_errored": len(rows) - total,
        "first_attempt_verified": sum(
            1 for r in completed if r["first_attempt_verified"]
        ),
        "verified_within_attempts": sum(
            1 for r in completed if r["verified_within_attempts"]
        ),
        "first_attempt_success_rate": (
            round(
                sum(1 for r in completed if r["first_attempt_verified"])
                / total, 4
            )
            if total else None
        ),
        "two_attempt_success_rate": (
            round(
                sum(1 for r in completed if r["verified_within_attempts"])
                / total, 4
            )
            if total else None
        ),
        "original_findings_total": originals,
        "original_findings_resolved_final": resolved,
        "new_findings_final": new_total,
        "syntax_valid_rate": (
            round(
                sum(1 for a in all_attempts if a["syntax_passed"])
                / len(all_attempts), 4
            )
            if all_attempts else None
        ),
        "generation_latency_seconds_total": (
            round(latency, 3) if latency is not None else None
        ),
        "attempts_with_latency": latency_attempts,
        "tokens_total": tokens,
        "attempts_with_token_usage": token_attempts,
        "functional_tests_status_counts": test_status,
        "note": (
            "Functional test results exist only when a user-supplied "
            "test file was run; otherwise the status is SKIPPED."
        ),
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "samples": rows,
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    target = (
        Path(output_path)
        if output_path
        else REPORTS_DIR / (
            f"evaluation_{version}_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
    )

    target.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8"
    )

    report["report_path"] = str(target)

    return report


def _main():
    parser = argparse.ArgumentParser(
        description="Run the SecureCodeAgent repair pipeline."
    )

    parser.add_argument("file", nargs="?", default=None)
    parser.add_argument("--test-file", default=None)
    parser.add_argument("--evaluate", default=None, metavar="SAMPLES_DIR")
    parser.add_argument(
        "--prompt",
        default=None,
        choices=sorted(
            v for v in PROMPT_VERSIONS if v != "feedback-v2"
        ),
    )
    parser.add_argument("--delay", type=int, default=0)
    parser.add_argument(
        "--attempts",
        type=int,
        default=MAX_REPAIR_ATTEMPTS
    )

    args = parser.parse_args()

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    )

    package_logger = logging.getLogger("securecodeagent")
    package_logger.addHandler(handler)
    package_logger.setLevel(logging.INFO)

    if args.evaluate:
        report = evaluate_samples(
            args.evaluate,
            prompt_version=args.prompt,
            max_attempts=args.attempts,
            delay_seconds=args.delay,
        )

        print(json.dumps(report["summary"], indent=2))
        print(f"\nFull report: {report['report_path']}")
        return 0

    if not args.file:
        parser.error("Provide a Python file or use --evaluate.")

    result = run_feedback_pipeline(
        args.file,
        test_file=args.test_file,
        max_attempts=args.attempts,
        prompt_version=args.prompt,
    )

    print(json.dumps(
        {k: v for k, v in result.items() if k != "verification_report"},
        indent=2,
        default=str
    ))

    return 0 if result["final_verdict"] in SUCCESS_VERDICTS else 1


if __name__ == "__main__":
    sys.exit(_main())