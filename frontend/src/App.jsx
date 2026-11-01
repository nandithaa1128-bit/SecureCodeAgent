
import { useEffect, useState } from 'react'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'
const MAX_ATTEMPTS = 2

const menuItems = [
  { name: 'Dashboard', icon: '▦' },
  { name: 'Scan History', icon: '⌕' },
  { name: 'Reports', icon: '▤' },
  { name: 'Prompt Evaluation', icon: '✦' },
]

async function postForm(endpoint, formData) {
  const response = await fetch(`${API_URL}${endpoint}`, {
    method: 'POST',
    body: formData,
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(
      data.detail || data.message || `Request failed (${response.status})`
    )
  }

  return data
}

function sessionForm(sessionId) {
  const formData = new FormData()
  formData.append('session_id', sessionId)
  return formData
}

function App() {
  const [activePage, setActivePage] = useState('Dashboard')
  const [selectedFile, setSelectedFile] = useState(null)

  const [scanResult, setScanResult] = useState(null)
  const [sessionId, setSessionId] = useState('')

  const [repairResult, setRepairResult] = useState(null)
  const [verification, setVerification] = useState(null)

  const [repairChoice, setRepairChoice] = useState(null)
  const [history, setHistory] = useState([])

  const [loading, setLoading] = useState(false)
  const [operation, setOperation] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const [copied, setCopied] = useState(false)
  const [showDiff, setShowDiff] = useState(false)

  const [evaluations, setEvaluations] = useState([])
  const [evaluationsLoading, setEvaluationsLoading] = useState(false)
  const [evaluationsError, setEvaluationsError] = useState('')

  const report = verification?.verification_report
  const checks = report?.checks

  const syntax = checks?.syntax
  const security = checks?.security_rescan
  const comparison = security?.comparison

  const functionalTests = checks?.functional_tests

  const testsRan =
    functionalTests?.status === 'PASSED' ||
    functionalTests?.status === 'FAILED'

  const unresolvedFindings =
    comparison?.unresolved_in_patch ||
    comparison?.unresolved_findings ||
    []

  const patchValidation = repairResult?.patch_validation
  const repairPlan = repairResult?.repair_plan || []
  const tokenUsage = repairResult?.token_usage

  const newFindings =
    comparison?.new_findings || []

  const unresolvedCount =
    verification?.assessment?.unresolved_findings ??
    comparison?.unresolved_count ??
    0

  const newCount =
    verification?.assessment?.new_findings ??
    comparison?.new_issues_count ??
    0

  const resolvedCount =
    comparison?.resolved_count ?? 0

  const attempt =
    verification?.attempt ??
    repairResult?.attempt ??
    0

  const verdict = verification?.verdict || ''

  const isSuccessful =
    verdict === 'REPAIR_SUCCESSFUL' ||
    verdict === 'VERIFIED_SECURE'

  const canRetry =
    verdict === 'VERIFICATION_FAILED' &&
    attempt < MAX_ATTEMPTS

  const displayVerdict = isSuccessful
    ? 'Repair successful'
    : verdict === 'VERIFICATION_FAILED'
      ? 'Verification failed'
      : verdict || 'Not verified'

  const addHistory = (item) => {
    setHistory((previous) => [
      {
        ...item,
        time: new Date().toLocaleString(),
      },
      ...previous,
    ])
  }

  // Upload and scan a Python file.
  const handleFileChange = async (event) => {
    const file = event.target.files?.[0]
    if (!file) return

    setError('')
    setMessage('')
    setScanResult(null)
    setRepairResult(null)
    setVerification(null)
    setSessionId('')
    setRepairChoice(null)
    setCopied(false)

    if (!file.name.toLowerCase().endsWith('.py')) {
      setSelectedFile(null)
      setError('Please upload a Python (.py) file.')
      event.target.value = ''
      return
    }

    if (file.size > 1_000_000) {
      setSelectedFile(null)
      setError('File size must be less than 1 MB.')
      event.target.value = ''
      return
    }

    setSelectedFile(file)
    await handleScan(file)
  }

  // Call the working backend scan endpoint.
  const handleScan = async (file) => {
    if (!file) return

    setLoading(true)
    setOperation('scan')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const data = await postForm('/api/scan', formData)

      setScanResult(data)
      setSessionId(data.session_id)

      addHistory({
        type: 'Vulnerability Scan',
        filename: file.name,
        result: `${data.total_issues} Bandit finding(s)`,
      })

    } catch (err) {
      setError(err.message || 'Security scan failed.')
    } finally {
      setLoading(false)
      setOperation('')
    }
  }

  // Generate a repair, then independently verify it.
  const startRepair = async () => {
    if (!sessionId) {
      setError('Please scan a Python file first.')
      return
    }

    setLoading(true)
    setOperation('repair')
    setError('')
    setMessage('')
    setVerification(null)
    setRepairResult(null)

    try {
      const repair = await postForm(
        '/api/repair',
        sessionForm(sessionId)
      )

      setRepairResult(repair)

      const result = await postForm(
        '/api/verify',
        sessionForm(sessionId)
      )

      setVerification(result)

      addHistory({
        type: 'Repair and Verification',
        filename: selectedFile?.name || 'Python file',
        result: `${result.verdict} · Attempt ${result.attempt}`,
      })

    } catch (err) {
      setError(err.message || 'Repair or verification failed.')
    } finally {
      setLoading(false)
      setOperation('')
    }
  }

  // Use actual verification feedback for another repair attempt.
  const retryRepair = async () => {
    if (!sessionId || !canRetry) return

    setLoading(true)
    setOperation('retry')
    setError('')
    setMessage('')
    setCopied(false)

    try {
      const repair = await postForm(
        '/api/retry-repair',
        sessionForm(sessionId)
      )

      setRepairResult(repair)

      const result = await postForm(
        '/api/verify',
        sessionForm(sessionId)
      )

      setVerification(result)

      addHistory({
        type: 'Feedback-based retry',
        filename: selectedFile?.name || 'Python file',
        result: `${result.verdict} · Attempt ${result.attempt}`,
      })

    } catch (err) {
      setError(err.message || 'Retry repair failed.')
    } finally {
      setLoading(false)
      setOperation('')
    }
  }

  // Copy the repaired code without downloading it.
  const copyCode = async () => {
    const code = repairResult?.patched_code

    if (!code) {
      setError('Repaired code is not available.')
      return
    }

    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setMessage('Repaired code copied to clipboard.')
    } catch {
      setError('Clipboard access failed. Please copy the code manually.')
    }
  }

  const loadEvaluations = async () => {
    setEvaluationsLoading(true)
    setEvaluationsError('')

    try {
      const response = await fetch(`${API_URL}/api/evaluations`)

      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`)
      }

      const data = await response.json()
      setEvaluations(data.runs || [])
    } catch (err) {
      setEvaluationsError(
        err.message || 'Could not load evaluation results.'
      )
    } finally {
      setEvaluationsLoading(false)
    }
  }

  useEffect(() => {
    if (activePage === 'Prompt Evaluation') {
      loadEvaluations()
    }
  }, [activePage])

  // Start a fresh workspace.
  const resetWorkspace = () => {
    setSelectedFile(null)
    setScanResult(null)
    setSessionId('')
    setRepairResult(null)
    setVerification(null)
    setRepairChoice(null)
    setError('')
    setMessage('')
    setCopied(false)
    setShowDiff(false)

    const input = document.getElementById('python-file')
    if (input) input.value = ''

    setActivePage('Dashboard')
  }

  const DashboardPage = () => (
    <>
      <section className="welcome-section">
        <div>
          <h2>Intelligent Code Security</h2>
          <p>
            Detect vulnerabilities, repair insecure code and
            verify proposed patches with agentic AI.
          </p>
        </div>
        <div className="security-badge">
          ✦ AI Powered Security
        </div>
      </section>

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon purple">⌕</div>
          <p>Total Scans</p>
          <h2>{history.filter(x => x.type === 'Vulnerability Scan').length}</h2>
          <span>Scans during this session</span>
        </div>

        <div className="stat-card">
          <div className="stat-icon red">⚠</div>
          <p>Vulnerabilities Found</p>
          <h2>{scanResult?.total_issues ?? '--'}</h2>
          <span>Bandit findings</span>
        </div>

        <div className="stat-card">
          <div className="stat-icon green">✓</div>
          <p>Issues Resolved</p>
          <h2>{verification ? resolvedCount : '--'}</h2>
          <span>Resolved original findings</span>
        </div>

        <div className="stat-card">
          <div className="stat-icon blue">◈</div>
          <p>Verification Status</p>
          <h2 className="verdict-text">
            {verification
              ? isSuccessful ? 'PASSED' : 'REVIEW'
              : '--'}
          </h2>
          <span>Latest patch verification</span>
        </div>
      </section>

      <section className="panel upload-panel">
        <div className="panel-heading">
          <div>
            <h2>Security Analysis Workspace</h2>
            <p>
              Upload a Python file to begin vulnerability detection.
            </p>
          </div>
          <span className="panel-icon">⌘</span>
        </div>

        <label className="upload-area">
          <input
            id="python-file"
            type="file"
            accept=".py"
            onChange={handleFileChange}
            disabled={loading}
          />

          <div className="upload-icon">↑</div>
          <h3>Upload Python Source Code</h3>
          <p>Click to select a Python file for analysis</p>
          <span className="file-hint">
            Python files only · Maximum 1 MB
          </span>
        </label>

        {selectedFile && (
          <div className="selected-file">
            <span>📄 {selectedFile.name}</span>
            <span>Selected</span>
          </div>
        )}

        {loading && (
          <div className="loading-panel">
            <div className="loading-spinner" />
            {operation === 'scan'
              ? 'Detecting vulnerabilities with Bandit...'
              : operation === 'retry'
                ? 'Groq is generating another repair using verification feedback...'
                : 'Generating repair and verifying the patch...'}
          </div>
        )}

        {error && (
          <div className="error-message" role="alert">
            <strong>Request could not be completed</strong>
            <p>{error}</p>
          </div>
        )}

        {message && (
          <div className="success-message" role="status">
            {message}
          </div>
        )}

        {scanResult && !loading && (
          <div className="scan-summary">
            <div>
              <span className="summary-label">
                Detection completed
              </span>
              <h3>
                {scanResult.total_issues} Bandit findings detected
              </h3>
              <p>File: {selectedFile?.name}</p>
            </div>
            <span className="step-status">Scan completed</span>
          </div>
        )}

        {scanResult?.findings?.length > 0 && (
          <div className="findings-list">
            <h3>Detected Vulnerabilities</h3>

            {scanResult.findings.map((finding, index) => (
              <div
                className="finding-item"
                key={`${finding.test_id}-${finding.line_number}-${index}`}
              >
                <div>
                  <strong>
                    {finding.test_id} — {finding.issue}
                  </strong>
                  <p>
                    Line {finding.line_number} · Confidence:{' '}
                    {finding.confidence}
                  </p>
                </div>

                <span
                  className={`severity-badge ${String(
                    finding.severity || ''
                  ).toLowerCase()}`}
                >
                  {finding.severity}
                </span>
              </div>
            ))}
          </div>
        )}

        {scanResult && scanResult.total_issues === 0 && (
          <div className="success-message">
            No Bandit vulnerabilities detected. This does not prove
            the program is free of bugs or security problems.
          </div>
        )}

        {scanResult && !repairChoice && !repairResult && !loading && (
          <div className="repair-action-area">
            <h3>Would you like to repair this code?</h3>
            <p>
              SecureCodeAgent can use Groq to propose a repair
              and independently verify the result.
            </p>

            <div className="action-buttons">
              <button
                className="repair-button"
                onClick={() => {
                  setRepairChoice('yes')
                  startRepair()
                }}
                disabled={scanResult.total_issues === 0}
              >
                Yes, repair my code
              </button>

              <button
                className="reset-button"
                onClick={() => {
                  setRepairChoice('no')
                  setMessage('Repair skipped. Your original file has not been changed.')
                }}
              >
                No, just show detection results
              </button>
            </div>
          </div>
        )}

        {repairChoice === 'no' && !repairResult && (
          <div className="success-message">
            Repair skipped. Your original uploaded file remains unchanged.
          </div>
        )}

        {verification && (
          <section className="repair-result" aria-live="polite">
            <div className="repair-result-heading">
              <div>
                <span className="result-eyebrow">
                  SECURECODEAGENT REPORT
                </span>
                <h3>Repair &amp; Verification</h3>
              </div>

              <span
                className={`verdict-pill ${
                  isSuccessful ? 'verified' : 'needs-review'
                }`}
              >
                <span className="verdict-dot" />
                {displayVerdict}
              </span>
            </div>

            <div
              className={`result-hero ${
                isSuccessful
                  ? 'result-hero-success'
                  : 'result-hero-warning'
              }`}
            >
              <div className="result-hero-icon">
                {isSuccessful ? '✓' : '!'}
              </div>

              <div className="result-hero-copy">
                <h2>
                  {isSuccessful
                    ? 'Patch passed available verification'
                    : 'Patch requires attention'}
                </h2>
                <p>
                  {report?.summary ||
                    'Review the verification results before using this patch.'}
                </p>
              </div>
            </div>

            <div className="verification-section">
              <div className="verification-section-heading">
                <h4>Verification checks</h4>
              </div>

              <div className="verification-check-grid">
                <div
                  className={`verification-check-card ${
                    syntax?.passed ? 'check-passed' : 'check-failed'
                  }`}
                >
                  <span className="check-icon">
                    {syntax?.passed ? '✓' : '!'}
                  </span>
                  <span className="check-label">Python syntax</span>
                  <strong>{syntax?.status || 'Unknown'}</strong>
                </div>

                <div
                  className={`verification-check-card ${
                    security?.scan_status === 'SUCCESS' &&
                    unresolvedCount === 0 &&
                    newCount === 0
                      ? 'check-passed'
                      : 'check-failed'
                  }`}
                >
                  <span className="check-icon">
                    {security?.scan_status === 'SUCCESS' &&
                    unresolvedCount === 0 &&
                    newCount === 0
                      ? '✓'
                      : '!'}
                  </span>
                  <span className="check-label">
                    Bandit security rescan
                  </span>
                  <strong>
                    {security?.scan_status || 'Unknown'}
                  </strong>
                </div>

                <div
                  className={`verification-check-card ${
                    functionalTests?.status === 'PASSED'
                      ? 'check-passed'
                      : testsRan || functionalTests?.status === 'ERROR'
                        ? 'check-failed'
                        : ''
                  }`}
                >
                  <span
                    className="check-icon"
                    style={
                      functionalTests?.status === 'PASSED' || testsRan
                        ? undefined
                        : { color: '#727b8e', background: '#eceef4' }
                    }
                  >
                    {functionalTests?.status === 'PASSED'
                      ? '✓'
                      : testsRan || functionalTests?.status === 'ERROR'
                        ? '!'
                        : '–'}
                  </span>
                  <span className="check-label">
                    Functional tests
                  </span>
                  <strong>
                    {testsRan
                      ? functionalTests.status
                      : 'Not executed'}
                  </strong>
                </div>
              </div>
            </div>

            <div className="repair-details-card">
              <div className="repair-details-heading">
                <h4>Repair details</h4>
                <span className="attempt-count">
                  Attempt {attempt} of {MAX_ATTEMPTS}
                </span>
              </div>

              <div className="repair-detail-row">
                <span>Repair source</span>
                <strong>Groq</strong>
              </div>

              <div className="repair-detail-row">
                <span>Resolved findings</span>
                <strong>{resolvedCount}</strong>
              </div>

              <div className="repair-detail-row">
                <span>Remaining original findings</span>
                <strong>{unresolvedCount}</strong>
              </div>

              <div className="repair-detail-row">
                <span>New findings</span>
                <strong>{newCount}</strong>
              </div>

              <div className="repair-detail-row">
                <span>Runtime behavior tested</span>
                <strong>
                  {verification.assessment?.runtime_behavior_tested
                    ? 'Yes'
                    : 'No'}
                </strong>
              </div>

              {repairResult?.prompt_version && (
                <div className="repair-detail-row">
                  <span>Prompt version</span>
                  <strong>{repairResult.prompt_version}</strong>
                </div>
              )}

              {patchValidation && (
                <div className="repair-detail-row">
                  <span>Preliminary patch validator</span>
                  <strong>
                    {patchValidation.passed ? 'Passed' : 'Failed'}
                    {patchValidation.warnings?.length
                      ? ` · ${patchValidation.warnings.length} warning(s)`
                      : ''}
                  </strong>
                </div>
              )}

              {repairResult?.latency_seconds != null && (
                <div className="repair-detail-row">
                  <span>Repair latency</span>
                  <strong>{repairResult.latency_seconds}s</strong>
                </div>
              )}

              {tokenUsage?.total_tokens != null && (
                <div className="repair-detail-row">
                  <span>Tokens used</span>
                  <strong>{tokenUsage.total_tokens}</strong>
                </div>
              )}

              <div className="repair-detail-row patch-file-row">
                <span>Patch file</span>
                <strong>
                  {repairResult?.patched_filename || 'Not available'}
                </strong>
              </div>
            </div>

            {(repairPlan.length > 0 ||
              patchValidation?.warnings?.length > 0) && (
              <div className="repair-action-area">
                <h3>Repair plan</h3>

                {repairPlan.map((item, index) => (
                  <div
                    className="finding-item"
                    key={`plan-${item.finding_id || index}`}
                  >
                    <div>
                      <strong>{item.finding_id}</strong>
                      <p>Root cause: {item.root_cause}</p>
                      <p>Fix: {item.proposed_fix}</p>
                      {item.why_previous_failed && (
                        <p>Why attempt 1 failed: {item.why_previous_failed}</p>
                      )}
                      {item.residual_risk && (
                        <p>Residual risk: {item.residual_risk}</p>
                      )}
                    </div>
                  </div>
                ))}

                {patchValidation?.warnings?.map((warning, index) => (
                  <div className="finding-item" key={`warn-${index}`}>
                    <div>
                      <strong>Validator warning</strong>
                      <p>{warning}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {repairResult?.patched_code && (
              <div className="repair-action-area">
                <h3>Repaired Python Code</h3>
                <p>
                  Review the proposed patch. Your original uploaded
                  file has not been overwritten.
                </p>

                <button
                  className="repair-button"
                  onClick={copyCode}
                >
                  {copied ? '✓ Code Copied' : 'Copy Repaired Code'}
                </button>

                <pre className="report-preview">
                  {repairResult.patched_code}
                </pre>
              </div>
            )}

            {(unresolvedFindings.length > 0 ||
              newFindings.length > 0) && (
              <div className="repair-action-area">
                <h3>Security findings requiring attention</h3>

                {unresolvedFindings.map((item, index) => (
                  <div className="finding-item" key={`unresolved-${index}`}>
                    <div>
                      <strong>
                        Unresolved: {item.test_id}
                      </strong>
                      <p>{item.issue}</p>
                      <p>Line {item.line_number} (repaired file)</p>
                    </div>
                  </div>
                ))}

                {newFindings.map((item, index) => (
                  <div className="finding-item" key={`new-${index}`}>
                    <div>
                      <strong>
                        New finding: {item.test_id}
                      </strong>
                      <p>{item.issue}</p>
                      <p>Line {item.line_number}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {canRetry && (
              <div className="retry-panel">
                <span className="retry-label">
                  VERIFICATION NEEDS ATTENTION
                </span>
                <h3>Would you like another repair attempt?</h3>
                <p>
                  Groq can use the actual verification findings
                  to generate one final patch. The server allows
                  at most {MAX_ATTEMPTS} repair attempts per file.
                </p>

                <div className="retry-details">
                  <span>Attempt {attempt} of {MAX_ATTEMPTS}</span>
                  <span>{unresolvedCount} unresolved</span>
                  <span>{newCount} new findings</span>
                </div>

                <button
                  className="repair-button"
                  onClick={retryRepair}
                  disabled={loading}
                >
                  Retry Repair →
                </button>
              </div>
            )}

            {verdict === 'VERIFICATION_FAILED' &&
              attempt >= MAX_ATTEMPTS && (
                <div className="error-message">
                  <strong>Maximum repair attempts reached</strong>
                  <p>
                    The patch has not passed verification.
                    Review the remaining findings before using it.
                  </p>
                </div>
              )}

            {isSuccessful && (
              <div className="success-message">
                <h3>Available verification checks passed</h3>
                <p>
                  Syntax and Bandit differential security checks
                  passed. Runtime behavior has not been established
                  unless a functional test suite was supplied and run.
                </p>
              </div>
            )}
          </section>
        )}

        {selectedFile && (
          <button
            className="reset-button"
            onClick={resetWorkspace}
            disabled={loading}
          >
            Clear Workspace / Upload New File
          </button>
        )}
      </section>

      <section className="panel activity-panel">
        <h2>Agentic Security Workflow</h2>
        <p className="panel-description">
          Detection, AI self-repair and independent patch verification.
        </p>

        {[
          ['01', 'Vulnerability Detection', 'Bandit static analysis after upload.',
            scanResult ? 'Completed' : 'Waiting', 'purple-bg'],
          ['02', 'AI Self-Repair', 'Groq repair using verification feedback.',
            repairResult ? 'Completed' : 'Waiting', 'blue-bg'],
          ['03', 'Patch Verification', 'Syntax validation and Bandit differential scan.',
            verification ? displayVerdict : 'Waiting', 'green-bg'],
        ].map(([number, title, description, status, color]) => (
          <div className="pipeline-step" key={number}>
            <div className={`step-number ${color}`}>{number}</div>
            <div>
              <h3>{title}</h3>
              <p>{description}</p>
            </div>
            <span className="step-status">{status}</span>
          </div>
        ))}
      </section>
    </>
  )

  const HistoryPage = () => (
    <>
      <div className="page-intro">
        <h2>Scan History</h2>
        <p>Review operations performed during this session.</p>
      </div>

      <div className="panel results-panel">
        {history.length === 0 ? (
          <div className="empty-activity">
            <h3>No scan history available</h3>
            <p>Upload a Python file to begin your first analysis.</p>
          </div>
        ) : (
          <div className="findings-list">
            {history.map((item, index) => (
              <div
                className="finding-item"
                key={`${item.type}-${item.time}-${index}`}
              >
                <div>
                  <strong>{item.type}</strong>
                  <p>{item.filename}</p>
                  <p>{item.result}</p>
                  <p>{item.time}</p>
                </div>
                <span className="step-status">Recorded</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  )

  const ReportsPage = () => (
    <>
      <div className="page-intro">
        <h2>Security Reports</h2>
        <p>Review the latest patch verification results.</p>
      </div>

      {!verification ? (
        <div className="panel empty-activity">
          <h3>No verification reports available</h3>
          <p>Complete a repair workflow to generate a report.</p>
        </div>
      ) : (
        <div className="panel results-panel">
          <h2>Latest Verification Report</h2>
          <p><strong>Verdict:</strong> {displayVerdict}</p>
          <p><strong>Resolved:</strong> {resolvedCount}</p>
          <p><strong>Unresolved:</strong> {unresolvedCount}</p>
          <p><strong>New issues:</strong> {newCount}</p>
          <p><strong>Attempt:</strong> {attempt} of {MAX_ATTEMPTS}</p>

          <div className="repair-detail-row">
            <span>Python syntax</span>
            <strong>{syntax?.status || 'Unknown'}</strong>
          </div>

          <div className="repair-detail-row">
            <span>Bandit security rescan</span>
            <strong>{security?.scan_status || 'Unknown'}</strong>
          </div>

          {report?.summary && (
            <p className="panel-description">{report.summary}</p>
          )}
        </div>
      )}
    </>
  )

  const PROMPT_ORDER = [
    ['baseline-v1', 'Baseline prompt'],
    ['optimized-rootcause-v2', 'Optimized root-cause prompt'],
  ]

  const latestByVersion = {}

  evaluations.forEach((run) => {
    const version = run.summary?.prompt_version_attempt_1

    if (version && !latestByVersion[version]) {
      latestByVersion[version] = run
    }
  })

  const evaluatedVersions = Object.keys(latestByVersion)

  const newestRun = evaluations[0]
  const newest = newestRun?.summary

  const percent = (value) =>
    value === null || value === undefined
      ? '—'
      : `${Math.round(value * 100)}%`

  const outOf = (count, total) =>
    count === null || count === undefined || total === null
      ? '—'
      : `${count} / ${total}`

  const comparisonRows = [
    ['Samples evaluated', (x) => x.samples_evaluated ?? '—'],
    ['First-attempt verified', (x) =>
      `${outOf(x.first_attempt_verified, x.samples_evaluated)} (${percent(x.first_attempt_success_rate)})`],
    ['Verified within 2 attempts', (x) =>
      `${outOf(x.verified_within_attempts, x.samples_evaluated)} (${percent(x.two_attempt_success_rate)})`],
    ['Original findings resolved', (x) =>
      outOf(x.original_findings_resolved_final, x.original_findings_total)],
    ['New findings introduced', (x) => x.new_findings_final ?? '—'],
    ['Syntax validity', (x) => percent(x.syntax_valid_rate)],
    ['Total tokens', (x) => x.tokens_total ?? 'Not available'],
    ['Total generation time', (x) =>
      x.generation_latency_seconds_total != null
        ? `${x.generation_latency_seconds_total}s`
        : 'Not available'],
    ['Functional tests', (x) =>
      Object.entries(x.functional_tests_status_counts || {})
        .map(([status, count]) => `${status}: ${count}`)
        .join(', ') || '—'],
  ]

  const cellStyle = {
    padding: '10px 12px',
    borderTop: '1px solid #eceef5',
    fontSize: '12px',
    textAlign: 'left',
    verticalAlign: 'top',
  }

  const PromptEvaluationPage = () => (
    <>
      <div className="page-intro">
        <h2>Prompt Evaluation and Optimization</h2>
        <p>
          Results below are read from evaluation runs saved in the
          reports folder. Nothing is estimated.
        </p>
      </div>

      <section className="stats-grid">
        <div className="stat-card">
          <p>Prompt Versions</p>
          <h2>
            {evaluationsLoading && !evaluations.length
              ? '…'
              : evaluatedVersions.length
                ? evaluatedVersions.length
                : 'Not measured'}
          </h2>
          <span>
            {evaluatedVersions.length
              ? `${evaluations.length} saved run(s)`
              : 'No evaluation runs found'}
          </span>
        </div>

        <div className="stat-card">
          <p>Repair Success Rate</p>
          <h2>
            {newest ? percent(newest.two_attempt_success_rate) : 'Not measured'}
          </h2>
          <span>
            {newest
              ? `Within 2 attempts · first try ${percent(newest.first_attempt_success_rate)}`
              : 'Awaiting evaluation data'}
          </span>
        </div>

        <div className="stat-card">
          <p>Syntax Validity</p>
          <h2>
            {newest ? percent(newest.syntax_valid_rate) : 'Not measured'}
          </h2>
          <span>
            {newest
              ? 'Share of generated patches that parse'
              : 'Awaiting evaluation data'}
          </span>
        </div>

        <div className="stat-card">
          <p>Vulnerability Reduction</p>
          <h2>
            {newest
              ? outOf(
                  newest.original_findings_resolved_final,
                  newest.original_findings_total
                )
              : 'Not measured'}
          </h2>
          <span>
            {newest
              ? `Latest run: ${newest.prompt_version_attempt_1}`
              : 'Awaiting evaluation data'}
          </span>
        </div>
      </section>

      <div className="panel results-panel">
        <div className="panel-heading">
          <div>
            <h2>Prompt Comparison</h2>
            <p>Newest saved run for each attempt-1 prompt version.</p>
          </div>

          <button
            className="reset-button"
            style={{ width: 'auto', marginTop: 0 }}
            onClick={loadEvaluations}
            disabled={evaluationsLoading}
          >
            {evaluationsLoading ? 'Loading…' : 'Refresh'}
          </button>
        </div>

        {evaluationsError && (
          <div className="error-message" role="alert">
            <strong>Could not load evaluation results</strong>
            <p>{evaluationsError}</p>
          </div>
        )}

        {!evaluationsError && !evaluationsLoading && !evaluations.length && (
          <p className="panel-description">
            No evaluation runs found. Run
            {' '}
            <code>
              python -m backend.pipeline --evaluate samples --prompt
              baseline-v1 --delay 65
            </code>
            {' '}
            and the same command with
            {' '}
            <code>optimized-rootcause-v2</code>, then click Refresh.
          </p>
        )}

        {evaluations.length > 0 && (
          <div style={{ overflowX: 'auto' }}>
            <table
              style={{ width: '100%', borderCollapse: 'collapse' }}
            >
              <thead>
                <tr>
                  <th style={{ ...cellStyle, borderTop: 'none' }}>Metric</th>
                  {PROMPT_ORDER.map(([version, label]) => (
                    <th
                      key={version}
                      style={{ ...cellStyle, borderTop: 'none' }}
                    >
                      {label}
                      <br />
                      <span style={{ color: '#9298a9', fontWeight: 400 }}>
                        {version}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {comparisonRows.map(([label, read]) => (
                  <tr key={label}>
                    <td style={{ ...cellStyle, color: '#727b8e' }}>{label}</td>

                    {PROMPT_ORDER.map(([version]) => {
                      const run = latestByVersion[version]

                      return (
                        <td key={version} style={cellStyle}>
                          {run ? (
                            <strong>{read(run.summary)}</strong>
                          ) : (
                            <span style={{ color: '#9298a9' }}>
                              Not evaluated
                            </span>
                          )}
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="findings-list" style={{ marginTop: 18 }}>
          <div className="finding-item">
            <div>
              <strong>Feedback-based prompt (feedback-v2)</strong>
              <p>
                Always used for attempt 2. Its effect is visible as the
                gap between first-attempt and two-attempt success.
              </p>
            </div>
            <span className="step-status">Used by repair pipeline</span>
          </div>
        </div>
      </div>

      {evaluations.length > 0 && (
        <div className="panel results-panel" style={{ marginTop: 20 }}>
          <h2>Saved Runs</h2>

          <div className="findings-list">
            {evaluations.map((run) => (
              <details
                className="finding-item"
                key={run.file}
                style={{ display: 'block' }}
              >
                <summary style={{ cursor: 'pointer' }}>
                  <strong>{run.summary?.prompt_version_attempt_1}</strong>
                  {' · '}
                  {run.summary?.samples_evaluated} sample(s) ·{' '}
                  {percent(run.summary?.two_attempt_success_rate)} verified
                  {' · '}
                  {run.generated_at
                    ? new Date(run.generated_at).toLocaleString()
                    : run.file}
                </summary>

                <div style={{ overflowX: 'auto', marginTop: 10 }}>
                  <table
                    style={{ width: '100%', borderCollapse: 'collapse' }}
                  >
                    <thead>
                      <tr>
                        {[
                          'Sample',
                          'Verdict',
                          'Attempts',
                          'First try',
                          'Resolved',
                          'New',
                        ].map((heading) => (
                          <th key={heading} style={cellStyle}>
                            {heading}
                          </th>
                        ))}
                      </tr>
                    </thead>

                    <tbody>
                      {(run.samples || []).map((sample) => (
                        <tr key={sample.sample}>
                          <td style={cellStyle}>{sample.sample}</td>
                          <td style={cellStyle}>
                            {sample.final_verdict || sample.status}
                          </td>
                          <td style={cellStyle}>
                            {sample.attempts_used ?? '—'}
                          </td>
                          <td style={cellStyle}>
                            {sample.first_attempt_verified === undefined
                              ? '—'
                              : sample.first_attempt_verified
                                ? 'Yes'
                                : 'No'}
                          </td>
                          <td style={cellStyle}>
                            {outOf(
                              sample.resolved_findings,
                              sample.original_findings
                            )}
                          </td>
                          <td style={cellStyle}>
                            {sample.new_findings ?? '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            ))}
          </div>
        </div>
      )}

      <div className="panel results-panel" style={{ marginTop: 20 }}>
        <h2>How to read these results</h2>
        <p className="panel-description">
          Success means the repaired file passed Python syntax checks
          and the Bandit differential rescan (every original finding
          gone, none new). Functional behavior is not tested unless a
          test file is supplied, so these numbers do not prove the
          repaired code still works. Model output varies between runs,
          and small sample sets give coarse percentages. Generation time
          includes any waiting caused by API rate limits.
        </p>
      </div>
    </>
  )

  const pages = {
    Dashboard: <DashboardPage />,
    'Scan History': <HistoryPage />,
    Reports: <ReportsPage />,
    'Prompt Evaluation': <PromptEvaluationPage />,
  }

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">S</div>
          <div>
            <h2>SecureCodeAgent</h2>
            <span>AI SECURITY PLATFORM</span>
          </div>
        </div>

        <p className="menu-label">WORKSPACE</p>

        <nav>
          {menuItems.map((item) => (
            <button
              key={item.name}
              className={`nav-item ${
                activePage === item.name ? 'active' : ''
              }`}
              onClick={() => setActivePage(item.name)}
            >
              <span>{item.icon}</span>
              {item.name}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          SecureCodeAgent
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="breadcrumb">
              Workspace / {activePage}
            </p>
            <h1>{activePage}</h1>
          </div>

          <div className="user-profile">
            <div className="avatar">SA</div>
            <span>Security Analyst</span>
          </div>
        </header>

        {pages[activePage]}

        <footer>
          SecureCodeAgent · Agentic AI Security Platform
        </footer>
      </main>
    </div>
  )
}

export default App
