
import json
import subprocess
import sys
from pathlib import Path


def scan_file(file_path):
    """Scan a Python file using Bandit and return structured findings."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-f",
            "json",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    # Bandit normally returns 1 when it finds issues.
    # Other nonzero return codes may indicate an execution problem.
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Bandit failed: {result.stderr or result.stdout}"
        )

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Could not parse Bandit's JSON output.") from exc

    findings = []

    for issue in report.get("results", []):
        findings.append(
            {
                "filename": issue.get("filename"),
                "line_number": issue.get("line_number"),
                "test_id": issue.get("test_id"),
                "issue": issue.get("issue_text"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
            }
        )

    return {
        "file": str(path),
        "total_issues": len(findings),
        "findings": findings,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detection/detector.py <python_file>")
        sys.exit(2)

    try:
        report = scan_file(sys.argv[1])
        print(json.dumps(report, indent=4))
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)
