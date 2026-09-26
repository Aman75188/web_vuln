import { useState, useEffect } from 'react'
import FindingCard from './components/FindingCard.jsx'
import SummaryBar from './components/SummaryBar.jsx'
import ModuleSelector from './components/ModuleSelector.jsx'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function App() {
  const [targetUrl, setTargetUrl] = useState('')
  const [confirmAuthorized, setConfirmAuthorized] = useState(false)
  const [availableModules, setAvailableModules] = useState([])
  const [selectedModules, setSelectedModules] = useState([])
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')

  useEffect(() => {
    fetch('/api/modules')
      .then((r) => r.json())
      .then((data) => {
        setAvailableModules(data.modules)
        setSelectedModules(data.modules)
      })
      .catch(() => setError('Could not reach the backend API. Is it running on :8000?'))
  }, [])

  async function runScan(e) {
    e.preventDefault()
    setError('')
    setResult(null)

    if (!targetUrl.trim()) {
      setError('Enter a target URL.')
      return
    }
    if (!confirmAuthorized) {
      setError('You must confirm you are authorized to test this target.')
      return
    }

    setScanning(true)
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          confirm_authorized: confirmAuthorized,
          modules: selectedModules,
        }),
      })
      const data = await resp.json()
      if (!resp.ok) {
        throw new Error(data.detail || 'Scan failed')
      }
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const filteredFindings = result
    ? result.findings
        .filter((f) => severityFilter === 'all' || f.severity === severityFilter)
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    : []

  return (
    <div className="min-h-screen max-w-4xl mx-auto px-4 py-8">
      <header className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight">Web Vulnerability Scanner</h1>
        <p className="text-slate-400 text-sm mt-1">
          Authorized-target scanner: headers, TLS, cookies, clickjacking, exposed paths, CSRF, reflected XSS, error-based SQLi.
        </p>
      </header>

      <form onSubmit={runScan} className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-1">Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:3000 or your lab target"
            className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
        </div>

        <ModuleSelector
          available={availableModules}
          selected={selectedModules}
          onChange={setSelectedModules}
        />

        <label className="flex items-start gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={confirmAuthorized}
            onChange={(e) => setConfirmAuthorized(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            I own this target, or have explicit written authorization to test it (e.g. my own lab, DVWA,
            OWASP Juice Shop). Active checks (XSS/SQLi probes) send test payloads to this app.
          </span>
        </label>

        <button
          type="submit"
          disabled={scanning}
          className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:cursor-not-allowed transition-colors px-4 py-2 rounded-md text-sm font-medium"
        >
          {scanning ? 'Scanning…' : 'Run Scan'}
        </button>

        {error && <p className="text-red-400 text-sm">{error}</p>}
      </form>

      {result && (
        <section className="mt-8">
          <SummaryBar
            summary={result.summary}
            targetUrl={result.target_url}
            activeFilter={severityFilter}
            onFilterChange={setSeverityFilter}
          />

          {result.errors?.length > 0 && (
            <div className="mt-4 bg-yellow-950/40 border border-yellow-800 rounded-md p-3 text-sm text-yellow-300">
              {result.errors.map((e, i) => (
                <p key={i}>{e}</p>
              ))}
            </div>
          )}

          <div className="mt-4 space-y-3">
            {filteredFindings.map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
            {filteredFindings.length === 0 && (
              <p className="text-slate-500 text-sm">No findings match this filter.</p>
            )}
          </div>
        </section>
      )}
    </div>
  )
}
