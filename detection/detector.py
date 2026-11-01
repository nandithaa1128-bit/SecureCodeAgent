import json
import subprocess
import sys
from pathlib import Path


def scan_file(file_path):
    """Scan a Python file using Bandit and return structured findings."""

    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    if path.suffix.lower() != ".py":
        raise ValueError(
            "Only Python (.py) files are supported."
        )

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-f",
        "json",
        "--ignore-nosec",
        str(path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Bandit scan timed out after 60 seconds."
        ) from exc

    except OSError as exc:
        raise RuntimeError(
            f"Could not start Bandit: {exc}"
        ) from exc

    # Parse JSON even when Bandit returns a non-zero exit code.
    # Bandit can return non-zero codes when findings are present.
    try:
        report = json.loads(result.stdout or "{}")

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Bandit did not produce valid JSON.\n"
            f"Exit code: {result.returncode}\n"
            f"Standard error: {result.stderr or '(empty)'}\n"
            f"Standard output: {result.stdout or '(empty)'}"
        ) from exc

    # A valid report must contain the expected results structure.
    if not isinstance(report, dict) or not isinstance(
        report.get("results"), list
    ):
        raise RuntimeError(
            "Bandit returned an unexpected JSON structure.\n"
            f"Exit code: {result.returncode}\n"
            f"Standard error: {result.stderr or '(empty)'}"
        )

    # Bandit can include errors inside its JSON report.
    errors = report.get("errors", [])

    if errors:
        raise RuntimeError(
            "Bandit reported scanning errors:\n"
            + json.dumps(errors, indent=2)
        )

    findings = []

    for issue in report.get("results", []):
        findings.append({
            "filename": issue.get("filename"),
            "line_number": issue.get("line_number"),
            "test_id": issue.get("test_id"),
            "issue": issue.get("issue_text"),
            "severity": issue.get("issue_severity"),
            "confidence": issue.get("issue_confidence"),
        })

    return {
        "file": str(path),
        "total_issues": len(findings),
        "findings": findings,
        "scan_status": "SUCCESS",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python detection/detector.py <python_file>",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        report = scan_file(sys.argv[1])

        print(
            json.dumps(report, indent=4)
        )

    except Exception as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        sys.exit(2)