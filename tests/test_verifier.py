"""
Unit Tests for Verification Agent (Member 3)
============================================
SecureCodeAgent Framework
"""

import tempfile
from pathlib import Path
import pytest

from verification.verifier import (
    check_syntax,
    compare_security_findings,
    determine_verdict,
    run_functional_tests,
    scan_file_security,
    verify_patch,
    format_report_markdown,
)


def test_syntax_check_valid():
    code = "def add(a, b):\n    return a + b\n"
    res = check_syntax(code)
    assert res["passed"] is True
    assert res["status"] == "PASSED"
    assert res["error"] is None


def test_syntax_check_invalid():
    code = "def broken(\n    return 42"
    res = check_syntax(code)
    assert res["passed"] is False
    assert res["status"] == "FAILED"
    assert "line" in res
    assert res["line"] is not None


def test_syntax_check_empty():
    res = check_syntax("")
    assert res["passed"] is False
    assert res["status"] == "FAILED"


def test_compare_security_findings():
    orig_findings = [
        {"test_id": "B602", "issue": "subprocess call with shell=True", "line_number": 4},
        {"test_id": "B105", "issue": "hardcoded password string", "line_number": 8},
    ]

    # Patch fixed B602, left B105, but introduced B307 (eval)
    patched_findings = [
        {"test_id": "B105", "issue": "hardcoded password string", "line_number": 8},
        {"test_id": "B307", "issue": "use of eval", "line_number": 12},
    ]

    diff = compare_security_findings(orig_findings, patched_findings)

    assert diff["original_count"] == 2
    assert diff["patched_count"] == 2
    assert diff["resolved_count"] == 1
    assert diff["unresolved_count"] == 1
    assert diff["new_issues_count"] == 1
    assert diff["resolved_findings"][0]["test_id"] == "B602"
    assert diff["new_findings"][0]["test_id"] == "B307"
    assert diff["resolution_rate_percent"] == 50.0
    assert diff["is_completely_clean"] is False


def test_determine_verdict_failed_syntax():
    syntax_fail = {"passed": False, "error": "SyntaxError at line 2"}
    diff = {"original_count": 1, "resolved_count": 0, "unresolved_count": 1, "new_issues_count": 0}
    test = {"status": "SKIPPED", "passed": None}

    verdict = determine_verdict(syntax_fail, diff, test)
    assert verdict["verdict"] == "VERIFICATION_FAILED"
    assert "Syntax error" in verdict["summary"]


def test_determine_verdict_new_vulnerability():
    syntax_ok = {"passed": True}
    diff = {"original_count": 1, "resolved_count": 1, "unresolved_count": 0, "new_issues_count": 1}
    test = {"status": "SKIPPED", "passed": None}

    verdict = determine_verdict(syntax_ok, diff, test)
    assert verdict["verdict"] == "VERIFICATION_FAILED"
    assert "new security vulnerability" in verdict["summary"]


def test_determine_verdict_partial_resolution():
    syntax_ok = {"passed": True}
    diff = {"original_count": 2, "resolved_count": 1, "unresolved_count": 1, "new_issues_count": 0}
    test = {"status": "SKIPPED", "passed": None}

    verdict = determine_verdict(syntax_ok, diff, test)
    assert verdict["verdict"] == "PARTIALLY_VERIFIED"


def test_determine_verdict_fully_verified():
    syntax_ok = {"passed": True}
    diff = {"original_count": 1, "resolved_count": 1, "unresolved_count": 0, "new_issues_count": 0}
    test = {"status": "PASSED", "passed": True}

    verdict = determine_verdict(syntax_ok, diff, test)
    assert verdict["verdict"] == "VERIFIED_SECURE"


def test_prevent_overwriting_original_file():
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        with pytest.raises(ValueError, match="must be different"):
            verify_patch(tmp_path, tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_end_to_end_verification_flow():
    # 1. Create a vulnerable sample file (hardcoded password -> B105)
    vulnerable_code = (
        'def get_db_secret():\n'
        '    secret = "hardcoded_secret_token_12345"\n'
        '    return secret\n'
    )

    # 2. Create a properly secured patch (retrieving from environment variable)
    secure_patched_code = (
        'import os\n'
        'def get_db_secret():\n'
        '    secret = os.getenv("DB_SECRET_TOKEN")\n'
        '    return secret\n'
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        orig_file = Path(tmpdir) / "vulnerable.py"
        patch_file = Path(tmpdir) / "patched.py"

        orig_file.write_text(vulnerable_code, encoding="utf-8")
        patch_file.write_text(secure_patched_code, encoding="utf-8")

        report = verify_patch(str(orig_file), str(patch_file))

        assert report["checks"]["syntax"]["passed"] is True
        comparison = report["checks"]["security_rescan"]["comparison"]
        assert comparison["original_count"] >= 1
        assert comparison["resolved_count"] >= 1
        assert comparison["is_completely_clean"] is True
        assert report["verdict"] == "VERIFIED_SECURE"

        # Check markdown generation works without error
        md = format_report_markdown(report)
        assert "VERIFIED SECURE" in md
