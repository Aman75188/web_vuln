const LABELS = {
  headers: 'Security Headers',
  cookies: 'Cookie Flags',
  clickjacking: 'Clickjacking',
  ssl_tls: 'SSL/TLS',
  tech_detect: 'Tech Fingerprint',
  dir_enum: 'Exposed Paths',
  csrf: 'CSRF Tokens',
  xss: 'Reflected XSS (active)',
  sqli: 'SQL Injection (active)',
}

export default function ModuleSelector({ available, selected, onChange }) {
  function toggle(mod) {
    if (selected.includes(mod)) {
      onChange(selected.filter((m) => m !== mod))
    } else {
      onChange([...selected, mod])
    }
  }

  if (!available.length) return null

  return (
    <div>
      <label className="block text-sm font-medium text-slate-300 mb-2">Checks to run</label>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {available.map((mod) => (
          <label key={mod} className="flex items-center gap-2 text-xs text-slate-300 bg-slate-950 border border-slate-800 rounded-md px-2 py-1.5">
            <input
              type="checkbox"
              checked={selected.includes(mod)}
              onChange={() => toggle(mod)}
            />
            {LABELS[mod] || mod}
          </label>
        ))}
      </div>
    </div>
  )
}
