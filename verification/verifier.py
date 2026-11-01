import ast
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================
# 1. PYTHON SYNTAX VALIDATION
# ============================================================

def check_syntax(source_code: str) -> Dict[str, Any]:
    """Validate Python syntax without executing the source."""

    if not source_code or not source_code.strip():
        return {
            "status": "FAILED",
            "passed": False,
            "error": "Source code is empty.",
            "line": None,
        }

    try:
        ast.parse(source_code)

        return {
            "status": "PASSED",
            "passed": True,
            "error": None,
            "line": None,
        }

    except SyntaxError as exc:
        return {
            "status": "FAILED",
            "passed": False,
            "error": f"{exc.msg} (line {exc.lineno})",
            "line": exc.lineno,
        }


# ============================================================
# 2. BANDIT SECURITY SCANNING
# ============================================================

def scan_file_security(file_path: str) -> Dict[str, Any]:
    """Scan a Python file with Bandit."""

    target = Path(file_path).resolve()

    if not target.is_file():
        return {
            "status": "ERROR",
            "error": f"File not found: {target}",
            "findings": [],
            "total_issues": 0,
        }

    if target.suffix.lower() != ".py":
        return {
            "status": "ERROR",
            "error": "Only Python files can be scanned.",
            "findings": [],
            "total_issues": 0,
        }

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                "-q",
                "--ignore-nosec",
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        if result.returncode not in (0, 1):
            return {
                "status": "ERROR",
                "error": (
                    result.stderr
                    or result.stdout
                    or "Bandit failed."
                ),
                "findings": [],
                "total_issues": 0,
            }

        data = json.loads(result.stdout or "{}")

        findings = []

        for issue in data.get("results", []):
            findings.append({
                "filename": issue.get("filename"),
                "test_id": issue.get("test_id"),
                "issue": issue.get("issue_text"),
                "line_number": issue.get("line_number"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
            })

        return {
            "status": "SUCCESS",
            "error": None,
            "findings": findings,
            "total_issues": len(findings),
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "ERROR",
            "error": "Bandit scan timed out after 60 seconds.",
            "findings": [],
            "total_issues": 0,
        }

    except (json.JSONDecodeError, OSError) as exc:
        return {
            "status": "ERROR",
            "error": f"Security scan failed: {exc}",
            "findings": [],
            "total_issues": 0,
        }


# ============================================================
# 3. COMPARE ORIGINAL AND PATCHED SECURITY FINDINGS
# ============================================================

def compare_security_findings(
    original_findings: List[Dict[str, Any]],
    patched_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare original and patched Bandit findings."""

    def finding_key(finding):
        return (
            finding.get("test_id"),
            finding.get("issue"),
        )

    pool = Counter(finding_key(f) for f in original_findings)

    unresolved_in_patch = []
    new_findings = []

    for finding in patched_findings:
        key = finding_key(finding)

        if pool[key] > 0:
            pool[key] -= 1
            unresolved_in_patch.append(finding)
        else:
            new_findings.append(finding)

    still_present = Counter(
        finding_key(f) for f in unresolved_in_patch
    )

    resolved = []
    unresolved = []

    for finding in original_findings:
        key = finding_key(finding)

        if still_present[key] > 0:
            still_present[key] -= 1
            unresolved.append(finding)
        else:
            resolved.append(finding)

    original_count = len(original_findings)

    resolution_rate = (
        len(resolved) / original_count * 100
        if original_count
        else 100.0
    )

    return {
        "original_count": original_count,
        "patched_count": len(patched_findings),
        "resolved_count": len(resolved),
        "unresolved_count": len(unresolved),
        "new_issues_count": len(new_findings),
        "resolution_rate_percent": round(
            resolution_rate, 2
        ),
        "resolved_findings": resolved,
        "unresolved_findings": unresolved,
        "unresolved_in_patch": unresolved_in_patch,
        "new_findings": new_findings,
        "patched_findings": patched_findings,
        "is_completely_clean": len(patched_findings) == 0,
    }


# ============================================================
# 4. FUNCTIONAL TEST EXECUTION
# ============================================================

def run_functional_tests(
    test_file_path: Optional[str] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Run explicitly supplied pytest tests.

    IMPORTANT:
    Tests execute Python code. Only provide trusted test files.
    Subprocess timeout does not constitute a security sandbox.
    """

    if not test_file_path:
        return {
            "status": "SKIPPED",
            "passed": None,
            "message": "No applicable test suite was provided.",
            "output": "",
        }

    test_path = Path(test_file_path).resolve()

    if not test_path.is_file():
        return {
            "status": "ERROR",
            "passed": None,
            "message": "The supplied test file does not exist.",
            "output": "",
        }

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(test_path),
                "-q",
                "--tb=short",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        passed = result.returncode == 0

        return {
            "status": "PASSED" if passed else "FAILED",
            "passed": passed,
            "message": (
                "Functional tests passed."
                if passed
                else "Functional tests failed."
            ),
            "output": (
                result.stdout + "\n" + result.stderr
            ).strip(),
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "FAILED",
            "passed": False,
            "message": f"Tests timed out after {timeout} seconds.",
            "output": "",
            "returncode": -1,
        }

    except Exception as exc:
        return {
            "status": "ERROR",
            "passed": None,
            "message": f"Test execution error: {exc}",
            "output": "",
        }


# ============================================================
# 5. DETERMINE VERIFICATION VERDICT
# ============================================================

def determine_verdict(
    syntax_result: Dict[str, Any],
    diff_result: Dict[str, Any],
    test_result: Dict[str, Any],
    security_scan_status: str = "SUCCESS",
) -> Dict[str, str]:
    """
    Determine repair success without overstating verification.

    Successful syntax and security checks are sufficient for
    REPAIR_SUCCESSFUL when no functional test suite is supplied.

    This does not claim runtime behavior has been tested.
    """

    # Syntax validation
    if not syntax_result.get("passed", False):
        return {
            "verdict": "VERIFICATION_FAILED",
            "summary": (
                "Repair failed: Python syntax validation failed. "
                f"{syntax_result.get('error')}"
            ),
        }

    # Security scan must complete successfully
    if security_scan_status != "SUCCESS":
        return {
            "verdict": "VERIFICATION_FAILED",
            "summary": (
                "Repair verification failed because the Bandit "
                "security scan could not be completed."
            ),
        }

    # New security issues
    if diff_result.get("new_issues_count", 0) > 0:
        return {
            "verdict": "VERIFICATION_FAILED",
            "summary": (
                "The repair introduced new Bandit security findings."
            ),
        }

    # Original issues still present
    if diff_result.get("unresolved_count", 0) > 0:
        return {
            "verdict": "VERIFICATION_FAILED",
            "summary": (
                "Some original Bandit security findings "
                "remain unresolved."
            ),
        }

    # Supplied tests failed
    if test_result.get("passed") is False:
        return {
            "verdict": "VERIFICATION_FAILED",
            "summary": "The supplied functional tests failed.",
        }

    if test_result.get("status") == "ERROR":
        return {
            "verdict": "VERIFICATION_FAILED",
            "summary": (
                "Functional test execution encountered an error."
            ),
        }

    # Syntax, security and supplied tests passed
    if test_result.get("status") == "PASSED":
        return {
            "verdict": "REPAIR_SUCCESSFUL",
            "summary": (
                "Python syntax validation, Bandit differential "
                "security checks, and supplied functional tests passed."
            ),
        }

    # No functional tests were supplied
    return {
        "verdict": "REPAIR_SUCCESSFUL",
        "summary": (
            "Python syntax validation and Bandit differential "
            "security checks passed. Functional behavior was "
            "not tested because no test suite was supplied."
        ),
    }


# ============================================================
# 6. VERIFY PATCH
# ============================================================

def verify_patch(
    original_file: str,
    patched_file: str,
    test_file: Optional[str] = None,
    original_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Verify a proposed patch without modifying original code."""

    original_path = Path(original_file).resolve()
    patch_path = Path(patched_file).resolve()

    if original_path == patch_path:
        raise ValueError(
            "Original and patched files must be different."
        )

    if not original_path.is_file():
        raise FileNotFoundError(
            f"Original file not found: {original_path}"
        )

    if not patch_path.is_file():
        raise FileNotFoundError(
            f"Patched file not found: {patch_path}"
        )

    if original_path.suffix.lower() != ".py":
        raise ValueError("Original file must be a Python file.")

    if patch_path.suffix.lower() != ".py":
        raise ValueError("Patched file must be a Python file.")

    patched_code = patch_path.read_text(
        encoding="utf-8"
    )

    syntax_result = check_syntax(patched_code)

    # Scan original code if baseline findings were not supplied.
    if original_findings is None:
        original_scan = scan_file_security(
            str(original_path)
        )

        if original_scan["status"] != "SUCCESS":
            raise RuntimeError(
                "Original security scan failed: "
                + original_scan.get("error", "Unknown error")
            )

        original_findings = original_scan["findings"]

    # Scan patched code only when syntax is valid.
    if syntax_result["passed"]:
        patch_scan = scan_file_security(
            str(patch_path)
        )
    else:
        patch_scan = {
            "status": "SKIPPED",
            "findings": [],
            "total_issues": 0,
            "error": (
                "Security scan skipped due to invalid syntax."
            ),
        }

    # Compare findings only when the scan succeeded.
    if patch_scan["status"] == "SUCCESS":
        diff_result = compare_security_findings(
            original_findings,
            patch_scan["findings"],
        )
    else:
        diff_result = {
            "original_count": len(original_findings),
            "patched_count": None,
            "resolved_count": 0,
            "unresolved_count": len(original_findings),
            "new_issues_count": 0,
            "resolution_rate_percent": 0.0,
            "resolved_findings": [],
            "unresolved_findings": original_findings,
            "unresolved_in_patch": [],
            "new_findings": [],
            "patched_findings": [],
            "is_completely_clean": False,
        }

    # Execute only an explicitly supplied test file.
    if syntax_result["passed"]:
        test_result = run_functional_tests(
            test_file
        )
    else:
        test_result = {
            "status": "SKIPPED",
            "passed": None,
            "message": (
                "Tests skipped because syntax validation failed."
            ),
            "output": "",
        }

    verdict_info = determine_verdict(
        syntax_result,
        diff_result,
        test_result,
        security_scan_status=patch_scan["status"],
    )

    return {
        "timestamp": datetime.now().isoformat(),

        "files": {
            "original_file": str(original_path),
            "patched_file": str(patch_path),
            "test_file": (
                str(Path(test_file).resolve())
                if test_file
                else None
            ),
        },

        "verdict": verdict_info["verdict"],
        "summary": verdict_info["summary"],

        "checks": {
            "syntax": syntax_result,

            "security_rescan": {
                "scan_status": patch_scan["status"],
                "scan_error": patch_scan.get("error"),
                "comparison": diff_result,
            },

            "functional_tests": test_result,
        },
    }


# ============================================================
# 7. FORMAT VERIFICATION REPORT
# ============================================================

def format_report_markdown(
    report: Dict[str, Any]
) -> str:
    """Format verification results as a Markdown report."""

    checks = report["checks"]

    syntax = checks["syntax"]
    security = checks["security_rescan"]
    comparison = security["comparison"]
    tests = checks["functional_tests"]

    lines = [
        "# SecureCodeAgent - Patch Verification Report",
        "",
        f"**Timestamp:** `{report['timestamp']}`",
        f"**Original file:** `{report['files']['original_file']}`",
        f"**Patched file:** `{report['files']['patched_file']}`",
        "",
        f"## Verdict: {report['verdict']}",
        f"> {report['summary']}",
        "",
        "## 1. Python Syntax Validation",
        f"- Status: **{syntax['status']}**",
    ]

    if syntax.get("error"):
        lines.append(
            f"- Error: {syntax['error']}"
        )

    lines.extend([
        "",
        "## 2. Bandit Security Verification",
        f"- Scan status: **{security['scan_status']}**",
    ])

    if security.get("scan_error"):
        lines.append(
            f"- Scan error: {security['scan_error']}"
        )

    lines.extend([
        f"- Original findings: {comparison['original_count']}",
        f"- Patched findings: {comparison['patched_count']}",
        f"- Resolved findings: {comparison['resolved_count']}",
        f"- Unresolved findings: {comparison['unresolved_count']}",
        f"- New findings: {comparison['new_issues_count']}",
        f"- Resolution rate: {comparison['resolution_rate_percent']}%",
    ])

    for title, key, line_key in (
        ("Unresolved findings (line numbers in patched file)",
         "unresolved_in_patch", "line_number"),
        ("New findings (line numbers in patched file)",
         "new_findings", "line_number"),
    ):
        items = comparison.get(key) or []

        if items:
            lines.extend(["", f"### {title}"])

            for item in items:
                lines.append(
                    f"- {item.get('test_id')} "
                    f"[{item.get('severity')}/{item.get('confidence')}] "
                    f"line {item.get(line_key)}: {item.get('issue')}"
                )

    lines.extend([
        "",
        "## 3. Functional Tests",
        f"- Status: **{tests['status']}**",
        f"- Details: {tests.get('message', 'N/A')}",
    ])

    if tests.get("output"):
        lines.extend([
            "",
            "### Test output",
            "```text",
            tests["output"],
            "```",
        ])

    lines.extend([
        "",
        "> A successful syntax and Bandit result does not prove "
        "that all runtime bugs or security vulnerabilities are absent.",
        "",
    ])

    return "\n".join(lines)


# ============================================================
# 8. COMMAND-LINE EXECUTION
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify a proposed Python patch."
    )

    parser.add_argument("original_file")
    parser.add_argument("patched_file")
    parser.add_argument("--test-file", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output-report", default=None)

    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(
            encoding="utf-8",
            errors="replace",
        )

    try:
        report = verify_patch(
            args.original_file,
            args.patched_file,
            args.test_file,
        )

        output = (
            json.dumps(report, indent=2)
            if args.json
            else format_report_markdown(report)
        )

        print(output)

        if args.output_report:
            report_path = Path(
                args.output_report
            ).resolve()

            report_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            report_path.write_text(
                output,
                encoding="utf-8",
            )

            print(
                f"\nReport saved to: {report_path}"
            )

        sys.exit(
            0 if report["verdict"] == "REPAIR_SUCCESSFUL" else 1
        )

    except Exception as exc:
        print(
            f"Verification error: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)