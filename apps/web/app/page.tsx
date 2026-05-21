export default function DashboardPage() {
  const stats = [
    {
      title: 'Total Findings',
      value: '1,248',
      change: '+12%',
    },
    {
      title: 'Critical Findings',
      value: '14',
      change: '-3%',
    },
    {
      title: 'High Severity',
      value: '37',
      change: '+8%',
    },
    {
      title: 'Scanners Active',
      value: '2',
      change: 'OpenVAS + ZAP',
    },
  ]

  const findings = [
    {
      id: 'FND-001',
      scanner: 'OpenVAS',
      host: '192.168.1.10',
      severity: 'critical',
      category: 'Remote Code Execution',
      createdAt: '2026-05-13',
    },
    {
      id: 'FND-002',
      scanner: 'ZAP',
      host: 'staging.rsky.local',
      severity: 'high',
      category: 'SQL Injection',
      createdAt: '2026-05-13',
    },
    {
      id: 'FND-003',
      scanner: 'OpenVAS',
      host: '10.0.0.25',
      severity: 'medium',
      category: 'Outdated Service',
      createdAt: '2026-05-12',
    },
  ]

  const severityStyles: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 border border-red-200',
    high: 'bg-orange-100 text-orange-700 border border-orange-200',
    medium: 'bg-yellow-100 text-yellow-700 border border-yellow-200',
    low: 'bg-green-100 text-green-700 border border-green-200',
  }

  return (
    <main className="min-h-screen bg-slate-100 p-8">
      <div className="mx-auto max-w-7xl space-y-8">
        {/* Header */}
        <section className="flex flex-col gap-2">
          <h1 className="text-4xl font-bold text-slate-900">
            Rsky Dashboard
          </h1>

          <p className="text-slate-600 text-lg">
            Contextual Risk Prioritiser overview for findings ingestion and
            vulnerability analysis.
          </p>
        </section>

        {/* Stats Grid */}
        <section className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
          {stats.map((stat) => (
            <div
              key={stat.title}
              className="rounded-2xl bg-white p-6 shadow-sm border border-slate-200"
            >
              <div className="space-y-3">
                <p className="text-sm font-medium text-slate-500">
                  {stat.title}
                </p>

                <h2 className="text-3xl font-bold text-slate-900">
                  {stat.value}
                </h2>

                <p className="text-sm text-slate-500">
                  {stat.change}
                </p>
              </div>
            </div>
          ))}
        </section>

        {/* Dashboard Layout */}
        <section className="grid grid-cols-1 gap-8 xl:grid-cols-3">
          {/* Findings Table */}
          <div className="xl:col-span-2 rounded-2xl bg-white border border-slate-200 shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-900">
                  Recent Findings
                </h2>

                <p className="text-sm text-slate-500 mt-1">
                  Latest findings inserted from OpenVAS and ZAP.
                </p>
              </div>

              <button className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 transition">
                Refresh
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Finding
                    </th>

                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Scanner
                    </th>

                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Host
                    </th>

                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Severity
                    </th>

                    <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Created
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-100 bg-white">
                  {findings.map((finding) => (
                    <tr key={finding.id} className="hover:bg-slate-50 transition">
                      <td className="px-6 py-4">
                        <div>
                          <p className="font-medium text-slate-900">
                            {finding.category}
                          </p>

                          <p className="text-sm text-slate-500">
                            {finding.id}
                          </p>
                        </div>
                      </td>

                      <td className="px-6 py-4 text-sm text-slate-700">
                        {finding.scanner}
                      </td>

                      <td className="px-6 py-4 text-sm text-slate-700">
                        {finding.host}
                      </td>

                      <td className="px-6 py-4">
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold capitalize ${severityStyles[finding.severity]}`}
                        >
                          {finding.severity}
                        </span>
                      </td>

                      <td className="px-6 py-4 text-sm text-slate-500">
                        {finding.createdAt}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Side Panel */}
          <div className="space-y-6">
            <div className="rounded-2xl bg-white border border-slate-200 p-6 shadow-sm">
              <h2 className="text-xl font-semibold text-slate-900">
                Scanner Status
              </h2>

              <div className="mt-5 space-y-4">
                <div className="flex items-center justify-between rounded-xl border border-slate-200 p-4">
                  <div>
                    <p className="font-medium text-slate-900">OpenVAS</p>
                    <p className="text-sm text-slate-500">Connector Active</p>
                  </div>

                  <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-700">
                    Online
                  </span>
                </div>

                <div className="flex items-center justify-between rounded-xl border border-slate-200 p-4">
                  <div>
                    <p className="font-medium text-slate-900">OWASP ZAP</p>
                    <p className="text-sm text-slate-500">Connector Active</p>
                  </div>

                  <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-700">
                    Online
                  </span>
                </div>
              </div>
            </div>

            <div className="rounded-2xl bg-white border border-slate-200 p-6 shadow-sm">
              <h2 className="text-xl font-semibold text-slate-900">
                Next Steps
              </h2>

              <ul className="mt-5 space-y-3 text-sm text-slate-600">
                <li>• Connect live Supabase queries</li>
                <li>• Add severity charts</li>
                <li>• Add authentication</li>
                <li>• Build finding detail page</li>
                <li>• Add filtering and pagination</li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
