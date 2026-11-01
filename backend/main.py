import difflib
import json
import logging
import re
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from detection.detector import scan_file
from repair.repair_agent import (
    append_repair_log,
    generate_patch_with_metadata,
    save_patch,
    PatchValidationError,
)
from verification.verifier import verify_patch, format_report_markdown

_package_logger = logging.getLogger("securecodeagent")

if not _package_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    )
    _package_logger.addHandler(_handler)
    _package_logger.setLevel(logging.INFO)


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORTS_DIR = PROJECT_ROOT / "reports"
WORKFLOWS_DIR = REPORTS_DIR / "workflows"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1_000_000

# Maximum number of Groq repair attempts per uploaded file.
# Enforced here on the server for every repair endpoint.
MAX_REPAIR_ATTEMPTS = 2

# Failed generations (API errors, rejected patches) do not use up a
# repair attempt but are capped so a session cannot loop forever.
MAX_GENERATION_FAILURES = 3

REPAIR_PROVIDER = "groq"

_active_sessions = set()
_active_lock = threading.Lock()


@contextmanager
def session_guard(session_id: str):
    with _active_lock:
        if session_id in _active_sessions:
            raise HTTPException(
                status_code=409,
                detail="Another operation is already running for this session."
            )

        _active_sessions.add(session_id)

    try:
        yield

    finally:
        with _active_lock:
            _active_sessions.discard(session_id)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SecureCodeAgent API",
    description=(
        "Agentic AI framework for Python vulnerability "
        "detection, code repair and patch verification."
    ),
    version="5.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def validate_python_file(file: UploadFile):
    if (
        not file.filename
        or not file.filename.lower().endswith(".py")
    ):
        raise HTTPException(
            status_code=400,
            detail="Only Python (.py) files are allowed."
        )


async def read_uploaded_file(file: UploadFile) -> str:
    validate_python_file(file)

    content = await file.read()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty."
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File size must be less than 1 MB."
        )

    try:
        return content.decode("utf-8")

    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="File must contain valid UTF-8 text."
        ) from exc


def safe_filename(filename: str) -> str:
    name = Path(filename).stem
    name = re.sub(r"[^A-Za-z0-9_-]", "_", name)

    return name[:80] or "uploaded_code"


def get_session_dir(session_id: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", session_id or ""):
        raise HTTPException(
            status_code=400,
            detail="Invalid session ID."
        )

    session_dir = (
        WORKFLOWS_DIR / session_id
    ).resolve()

    if not session_dir.is_relative_to(
        WORKFLOWS_DIR.resolve()
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid session path."
        )

    return session_dir


def load_session(session_id: str) -> dict:
    session_dir = get_session_dir(session_id)
    metadata_path = session_dir / "session.json"

    if not metadata_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Session not found. Please upload your file again."
        )

    try:
        return json.loads(
            metadata_path.read_text(encoding="utf-8")
        )

    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not read the workflow session."
        ) from exc


def save_session(session_id: str, data: dict):
    session_dir = get_session_dir(session_id)
    session_dir.mkdir(parents=True, exist_ok=True)

    metadata_path = session_dir / "session.json"
    temporary_path = session_dir / "session.tmp"

    temporary_path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )

    temporary_path.replace(metadata_path)


def make_change_summary(
    original_code: str,
    patched_code: str
) -> dict:

    original_lines = original_code.splitlines()
    patched_lines = patched_code.splitlines()

    diff_lines = list(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile="original.py",
            tofile="repaired.py",
            lineterm="",
            n=3
        )
    )

    added = [
        line[1:]
        for line in diff_lines
        if line.startswith("+")
        and not line.startswith("+++")
    ]

    removed = [
        line[1:]
        for line in diff_lines
        if line.startswith("-")
        and not line.startswith("---")
    ]

    return {
        "lines_added": len(added),
        "lines_removed": len(removed),
        "change_count": len(added) + len(removed),
        "diff": "\n".join(diff_lines)
    }


# ============================================================
# REPAIR HELPERS
# ============================================================

def register_generation_failure(session_id: str, session: dict, stage: str, error):
    session["generation_failures"] = (
        session.get("generation_failures", 0) + 1
    )

    session["last_generation_error"] = {
        "stage": stage,
        "message": str(error)[:2000]
    }

    save_session(session_id, session)


def ensure_generation_allowed(session: dict):
    if session.get("generation_failures", 0) >= MAX_GENERATION_FAILURES:
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed repair generations for this session. "
                "Upload the file again to start a new session."
            )
        )


def describe_repair(metadata: dict) -> dict:
    validation = metadata.get("validation") or {}

    return {
        "prompt_version": metadata.get("prompt_version"),
        "model": metadata.get("model"),
        "latency_seconds": metadata.get("latency_seconds"),
        "token_usage": metadata.get("token_usage"),
        "api_calls": metadata.get("api_calls"),
        "format_retries": metadata.get("format_retries"),
        "repair_plan": metadata.get("plan") or [],
        "repair_plan_parsed": metadata.get("plan_parsed", False),
        "patch_validation": {
            "passed": validation.get("passed"),
            "errors": validation.get("errors", []),
            "warnings": validation.get("warnings", []),
            "checks": validation.get("checks", {}),
        },
    }


# ============================================================
# REPAIR ASSESSMENT
# ============================================================

def get_repair_assessment(report: dict) -> dict:
    """
    Assess syntax and security separately from runtime behavior.
    Never claim that unexecuted functional tests passed.
    """

    checks = report.get("checks", {})

    syntax = checks.get("syntax", {})
    security = checks.get("security_rescan", {})

    comparison = security.get("comparison", {})

    syntax_status = str(
        syntax.get("status", "")
    ).upper()

    syntax_passed = (
        syntax_status in {
            "PASSED",
            "PASS",
            "SUCCESS"
        }
        or syntax.get("passed") is True
    )

    scan_status = str(
        security.get("scan_status", "")
    ).upper()

    scan_passed = scan_status in {
        "SUCCESS",
        "PASSED",
        "PASS"
    }

    unresolved = comparison.get(
        "unresolved_count",
        len(comparison.get("unresolved_findings", []))
    )

    new_issues = comparison.get(
        "new_issues_count",
        len(comparison.get("new_findings", []))
    )

    security_passed = (
        scan_passed
        and unresolved == 0
        and new_issues == 0
    )

    tests = checks.get("functional_tests", {})
    tests_status = str(tests.get("status", "SKIPPED")).upper()

    runtime_tested = tests_status in {"PASSED", "FAILED"}

    tests_ok = (
        tests_status not in {"FAILED", "ERROR"}
        and tests.get("passed") is not False
    )

    return {
        "syntax_passed": syntax_passed,
        "security_passed": security_passed,

        "unresolved_findings": unresolved,
        "new_findings": new_issues,

        "functional_tests_status": tests_status,

        "repair_successful": (
            syntax_passed and security_passed and tests_ok
        ),

        "runtime_behavior_tested": runtime_tested,

        "runtime_note": (
            "Supplied functional tests were executed."
            if runtime_tested
            else (
                "Functional behavior has not been established. "
                "No user-supplied test suite was run and generated "
                "candidate tests are not executed."
            )
        )
    }


# ============================================================
# HOME AND HEALTH
# ============================================================

@app.get("/")
def home():
    return {
        "service": "SecureCodeAgent API",
        "status": "running",
        "provider": REPAIR_PROVIDER,
        "maximum_repair_attempts": MAX_REPAIR_ATTEMPTS
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecureCodeAgent API",
        "repair_provider": REPAIR_PROVIDER,
        "maximum_repair_attempts": MAX_REPAIR_ATTEMPTS
    }


# ============================================================
# STEP 1: DETECT VULNERABILITIES
# ============================================================

@app.post("/api/scan")
async def scan_python_file(
    file: UploadFile = File(...)
):

    source_code = await read_uploaded_file(file)

    session_id = uuid.uuid4().hex

    session_dir = get_session_dir(session_id)
    session_dir.mkdir(parents=True, exist_ok=True)

    original_path = session_dir / "original.py"

    original_path.write_text(
        source_code,
        encoding="utf-8"
    )

    try:
        report = await run_in_threadpool(
            scan_file,
            str(original_path)
        )

        findings = report.get("findings", [])

        session_data = {
            "session_id": session_id,
            "filename": file.filename,
            "original_path": str(original_path),

            "total_issues": report.get(
                "total_issues", 0
            ),

            "findings": findings,

            "attempts_used": 0,
            "latest_patch": None,
            "latest_report": None,

            "history": [],
            "status": "SCANNED"
        }

        save_session(session_id, session_data)

        return {
            "status": "success",
            "session_id": session_id,
            "filename": file.filename,

            "total_issues": session_data["total_issues"],
            "findings": findings,

            "repair_required": (
                session_data["total_issues"] > 0
            ),

            "maximum_repair_attempts": MAX_REPAIR_ATTEMPTS,

            "message": (
                "Detection completed. Choose whether you want "
                "SecureCodeAgent to repair the detected issues."
            )
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {error}"
        ) from error


# ============================================================
# STEP 2: FIRST REPAIR ATTEMPT (ROOT-CAUSE REPAIR)
# ============================================================

@app.post("/api/repair")
async def repair_python_file(
    session_id: str = Form(...)
):

    with session_guard(session_id):

        session = load_session(session_id)

        if session["attempts_used"] >= MAX_REPAIR_ATTEMPTS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Maximum of {MAX_REPAIR_ATTEMPTS} "
                    "repair attempts reached."
                )
            )

        if session["attempts_used"] != 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The initial repair has already been generated. "
                    "Use the feedback-based retry endpoint instead."
                )
            )

        if session["total_issues"] == 0:
            raise HTTPException(
                status_code=400,
                detail="No Bandit findings were detected. Repair is not required."
            )

        ensure_generation_allowed(session)

        original_path = Path(session["original_path"])

        original_code = original_path.read_text(
            encoding="utf-8"
        )

        attempt = session["attempts_used"] + 1

        patch_path = (
            get_session_dir(session_id)
            / f"repaired_v{attempt}.py"
        )

        try:
            patched_code, metadata = await run_in_threadpool(
                lambda: generate_patch_with_metadata(
                    original_code,
                    findings=session["findings"],
                    attempt=1
                )
            )

            save_patch(
                patched_code,
                patch_path,
                original_path=original_path
            )

        except Exception as error:
            register_generation_failure(
                session_id, session, "initial_repair", error
            )

            status_code = (
                422 if isinstance(error, PatchValidationError) else 502
            )

            raise HTTPException(
                status_code=status_code,
                detail=f"Groq repair failed: {error}"
            ) from error

        repair_info = describe_repair(metadata)

        session["attempts_used"] = attempt
        session["latest_patch"] = str(patch_path)
        session["latest_report"] = None
        session["status"] = "REPAIR_GENERATED"

        session.setdefault("repairs", []).append({
            "attempt": attempt,
            "patch": str(patch_path),
            **repair_info
        })

        save_session(session_id, session)

        return {
            "status": "success",

            "message": (
                "Groq generated the first proposed repair. "
                "Independent verification is required."
            ),

            "session_id": session_id,
            "attempt": attempt,

            "patched_filename": patch_path.name,
            "patched_code": patched_code,

            "changes": make_change_summary(
                original_code,
                patched_code
            ),

            "repair_source": REPAIR_PROVIDER,
            "verification_status": "NOT_VERIFIED",

            "attempts_remaining": (
                MAX_REPAIR_ATTEMPTS - attempt
            ),

            **repair_info
        }


# ============================================================
# STEP 3: VERIFY THE LATEST REPAIR
# ============================================================

@app.post("/api/verify")
async def verify_python_repair(
    session_id: str = Form(...)
):

    with session_guard(session_id):
        return await run_verification(session_id)


async def run_verification(session_id: str):

    session = load_session(session_id)

    patch_path = session.get("latest_patch")

    if not patch_path or not Path(patch_path).is_file():
        raise HTTPException(
            status_code=400,
            detail="No repaired code is available to verify."
        )

    if session.get("latest_report"):
        raise HTTPException(
            status_code=400,
            detail="The latest patch has already been verified."
        )

    original_path = Path(session["original_path"])

    try:
        report = await run_in_threadpool(
            verify_patch,
            str(original_path),
            patch_path,
            None,
            session["findings"]
        )

        assessment = get_repair_assessment(report)

        report_path = (
            get_session_dir(session_id)
            / f"verification_v{session['attempts_used']}.md"
        )

        report_path.write_text(
            format_report_markdown(report),
            encoding="utf-8"
        )

        session["latest_report"] = report

        session["status"] = (
            "REPAIR_SUCCESSFUL"
            if assessment["repair_successful"]
            else "VERIFICATION_FAILED"
        )

        session["history"].append({
            "attempt": session["attempts_used"],
            "verdict": report.get("verdict"),
            "assessment": assessment,
            "report_path": str(report_path)
        })

        save_session(session_id, session)

        comparison = (
            report.get("checks", {})
            .get("security_rescan", {})
            .get("comparison", {})
        )

        last_repair = (session.get("repairs") or [{}])[-1]

        append_repair_log({
            "event": "verification",
            "attempt": session["attempts_used"],
            "prompt_version": last_repair.get("prompt_version"),
            "verdict": report.get("verdict"),
            "repair_successful": assessment["repair_successful"],
            "syntax_passed": assessment["syntax_passed"],
            "original_count": comparison.get("original_count"),
            "resolved_count": comparison.get("resolved_count"),
            "unresolved_count": comparison.get("unresolved_count"),
            "new_issues_count": comparison.get("new_issues_count"),
            "functional_tests_status": assessment["functional_tests_status"],
        })

        patched_code = Path(patch_path).read_text(
            encoding="utf-8"
        )

        original_code = original_path.read_text(
            encoding="utf-8"
        )

        attempts_remaining = (
            MAX_REPAIR_ATTEMPTS - session["attempts_used"]
        )

        return {
            "status": "success",

            "session_id": session_id,
            "attempt": session["attempts_used"],

            "verdict": (
                "REPAIR_SUCCESSFUL"
                if assessment["repair_successful"]
                else "VERIFICATION_FAILED"
            ),

            "assessment": assessment,
            "verification_report": report,

            "patched_code": patched_code,

            "changes": make_change_summary(
                original_code,
                patched_code
            ),

            "can_retry": (
                not assessment["repair_successful"]
                and attempts_remaining > 0
            ),

            "attempts_remaining": attempts_remaining
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Verification failed: {error}"
        ) from error


# ============================================================
# STEP 4: SECOND REPAIR ATTEMPT USING VERIFICATION FEEDBACK
# ============================================================

@app.post("/api/retry-repair")
async def retry_repair(
    session_id: str = Form(...)
):

    with session_guard(session_id):

        session = load_session(session_id)

        if session["attempts_used"] >= MAX_REPAIR_ATTEMPTS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Maximum of {MAX_REPAIR_ATTEMPTS} "
                    "repair attempts reached."
                )
            )

        if session["attempts_used"] != 1:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Feedback-based retry is available only "
                    "after the first repair attempt."
                )
            )

        if not session.get("latest_report"):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Verify the latest patch before requesting a retry."
                )
            )

        assessment = get_repair_assessment(
            session["latest_report"]
        )

        if assessment["repair_successful"]:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The latest repair passed the available verification "
                    "checks. Another repair is not required."
                )
            )

        ensure_generation_allowed(session)

        latest_patch = Path(session["latest_patch"])

        if not latest_patch.is_file():
            raise HTTPException(
                status_code=404,
                detail="Latest repaired source file not found."
            )

        original_path = Path(session["original_path"])

        original_code = original_path.read_text(
            encoding="utf-8"
        )

        latest_code = latest_patch.read_text(
            encoding="utf-8"
        )

        attempt = session["attempts_used"] + 1

        patch_path = (
            get_session_dir(session_id)
            / f"repaired_v{attempt}.py"
        )

        try:
            patched_code, metadata = await run_in_threadpool(
                lambda: generate_patch_with_metadata(
                    latest_code,
                    findings=session["findings"],
                    original_source=original_code,
                    verification_report=session["latest_report"],
                    attempt=2
                )
            )

            save_patch(
                patched_code,
                patch_path,
                original_path=original_path
            )

        except Exception as error:
            register_generation_failure(
                session_id, session, "retry_repair", error
            )

            status_code = (
                422 if isinstance(error, PatchValidationError) else 502
            )

            raise HTTPException(
                status_code=status_code,
                detail=f"Groq retry failed: {error}"
            ) from error

        repair_info = describe_repair(metadata)

        session["attempts_used"] = attempt
        session["latest_patch"] = str(patch_path)
        session["latest_report"] = None
        session["status"] = "REPAIR_GENERATED"

        session.setdefault("repairs", []).append({
            "attempt": attempt,
            "patch": str(patch_path),
            **repair_info
        })

        save_session(session_id, session)

        return {
            "status": "success",

            "message": (
                "The second repair attempt was generated "
                "using actual verification feedback."
            ),

            "session_id": session_id,
            "attempt": attempt,

            "patched_filename": patch_path.name,
            "patched_code": patched_code,

            "changes": make_change_summary(
                original_code,
                patched_code
            ),

            "repair_source": REPAIR_PROVIDER,
            "verification_status": "NOT_VERIFIED",

            "attempts_remaining": (
                MAX_REPAIR_ATTEMPTS - attempt
            ),

            **repair_info
        }


# ============================================================
# PROMPT EVALUATION RESULTS
# ============================================================

@app.get("/api/evaluations")
def list_evaluations(limit: int = 20):

    runs = []

    paths = sorted(
        REPORTS_DIR.glob("evaluation_*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True
    )

    for path in paths[:max(1, min(limit, 50))]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        summary = data.get("summary")

        if not isinstance(summary, dict):
            continue

        runs.append({
            "file": path.name,
            "generated_at": data.get("generated_at"),
            "summary": summary,
            "samples": data.get("samples", [])
        })

    return {"runs": runs}


# ============================================================
# STEP 5: WORKFLOW STATUS
# ============================================================

@app.get("/api/session/{session_id}")
def get_workflow_status(session_id: str):

    session = load_session(session_id)

    return {
        "status": session.get("status"),
        "session_id": session_id,
        "filename": session.get("filename"),

        "total_issues": session.get("total_issues", 0),

        "attempts_used": session.get("attempts_used", 0),

        "attempts_remaining": (
            MAX_REPAIR_ATTEMPTS
            - session.get("attempts_used", 0)
        ),

        "maximum_repair_attempts": MAX_REPAIR_ATTEMPTS,

        "history": session.get("history", [])
    }