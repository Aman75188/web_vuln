const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const COLORS = {
  critical: 'bg-red-600',
  high: 'bg-orange-600',
  medium: 'bg-yellow-600',
  low: 'bg-blue-600',
  info: 'bg-slate-600',
}

export default function SummaryBar({ summary, targetUrl, activeFilter, onFilterChange }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (summary[s] || 0), 0)

  return (
    <div>
      <p className="text-sm text-slate-400 mb-2">
        Scanned <span className="text-slate-200 font-medium">{targetUrl}</span> — {total} finding(s)
      </p>
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => onFilterChange('all')}
          className={`px-3 py-1 rounded-full text-xs font-medium border ${
            activeFilter === 'all' ? 'bg-slate-200 text-slate-900' : 'border-slate-700 text-slate-300'
          }`}
        >
          All ({total})
        </button>
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            onClick={() => onFilterChange(sev)}
            className={`px-3 py-1 rounded-full text-xs font-medium text-white ${COLORS[sev]} ${
              activeFilter === sev ? 'ring-2 ring-white' : 'opacity-70'
            }`}
          >
            {sev} ({summary[sev] || 0})
          </button>
        ))}
      </div>
    </div>
  )
}
