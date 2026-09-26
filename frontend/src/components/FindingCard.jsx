const SEVERITY_STYLES = {
  critical: 'border-l-severity-critical bg-red-950/20 text-red-300',
  high: 'border-l-severity-high bg-orange-950/20 text-orange-300',
  medium: 'border-l-severity-medium bg-yellow-950/20 text-yellow-300',
  low: 'border-l-severity-low bg-blue-950/20 text-blue-300',
  info: 'border-l-severity-info bg-slate-800/40 text-slate-300',
}

export default function FindingCard({ finding }) {
  const style = SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.info

  return (
    <div className={`border-l-4 rounded-md p-4 bg-slate-900 border border-slate-800 ${style.split(' ')[0]}`}>
      <div className="flex items-center justify-between gap-2">
        <h3 className="font-medium text-slate-100">{finding.title}</h3>
        <span className={`text-xs uppercase font-semibold px-2 py-0.5 rounded ${style}`}>
          {finding.severity}
        </span>
      </div>
      <p className="text-sm text-slate-400 mt-1">{finding.description}</p>
      {finding.evidence && (
        <p className="text-xs font-mono text-slate-500 mt-2 bg-slate-950 rounded p-2 overflow-x-auto">
          {finding.evidence}
        </p>
      )}
      {finding.recommendation && (
        <p className="text-xs text-emerald-400 mt-2">
          <span className="font-semibold">Fix: </span>
          {finding.recommendation}
        </p>
      )}
      <p className="text-xs text-slate-600 mt-2">
        Module: {finding.module}
        {finding.url ? ` • ${finding.url}` : ''}
      </p>
    </div>
  )
}
