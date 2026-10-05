import { ArrowUpRight, ChevronDown, TriangleAlert } from 'lucide-react'
import { type ReactNode, useState } from 'react'
import { Link } from 'react-router'
import type { Dashboard } from '@/api/dashboard'
import { formatUtc } from '@/lib/format'
import { trendText } from '@/lib/overview'
import { cn } from '@/lib/utils'

const TILE = 'group relative flex flex-col rounded-xl border bg-card p-4 text-left transition-colors hover:border-primary/60 hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none'

function Body({ label, value, sub, alert }: { label: string; value: number; sub: ReactNode; alert?: boolean }) {
  return (
    <>
      <ArrowUpRight className="absolute top-3 right-3 size-4 text-muted-foreground opacity-60 transition-opacity group-hover:opacity-100" aria-hidden />
      <p className="label-caps pr-6">{label}</p>
      <p className="mt-1 metric">{value.toLocaleString()}</p>
      <p className={cn('mt-1 flex items-center gap-1 text-xs', alert ? 'text-destructive' : 'text-muted-foreground')}>
        {alert && <TriangleAlert className="size-3.5" aria-hidden />}
        {sub}
      </p>
    </>
  )
}

/** Security overview tiles. Each opens exactly what its number counts. */
export default function KpiTiles({ kpis, datasets }: { kpis: Dashboard['kpis']; datasets: Dashboard['datasets'] }) {
  const [showDatasets, setShowDatasets] = useState(false)
  const k = kpis
  return (
    <div className="flex flex-col gap-3">
      {/* One strip across the top of the dashboard on wide screens. */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <button type="button" className={TILE} aria-expanded={showDatasets} aria-controls="dataset-breakdown"
                onClick={() => setShowDatasets((v) => !v)}>
          <Body label="Events analyzed" value={k.events}
                sub={trendText(k.events_last_period, k.events_previous_period ?? null, k.period_days)} />
        </button>
        <Link to="/rules" className={TILE}>
          <Body label="Anomalies detected" value={k.findings} sub={`${k.findings_high.toLocaleString()} high or critical`} />
        </Link>
        <Link to="/investigations?status=open,investigating" className={TILE}>
          <Body label="Open investigations" value={k.open_cases}
                sub={k.unassigned_urgent > 0 ? `${k.unassigned_urgent} unassigned critical/high` : 'All critical/high assigned'}
                alert={k.unassigned_urgent > 0} />
        </Link>
        <Link to="/investigations?severity=critical" className={TILE}>
          <Body label="Critical" value={k.critical} sub={k.critical > 0 ? 'Needs review' : 'None'} alert={k.critical > 0} />
        </Link>
        <Link to="/users?severity=critical,high" className={TILE}>
          <Body label="High-risk entities" value={k.high_risk_users + k.high_risk_ips}
                sub={`${k.high_risk_users} user${k.high_risk_users === 1 ? '' : 's'} · ${k.high_risk_ips} IP${k.high_risk_ips === 1 ? '' : 's'}`} />
        </Link>
      </div>

      {showDatasets && (
        <section id="dataset-breakdown" className="rounded-xl border bg-card p-4">
          <div className="flex items-center justify-between gap-2">
            <h2 className="section-title">Events by dataset</h2>
            <button type="button" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
                    onClick={() => setShowDatasets(false)}>
              Hide <ChevronDown className="size-4 rotate-180" aria-hidden />
            </button>
          </div>
          <p className="meta mt-1">Each distinct dataset once (re-uploads are counted once); open one in Logs.</p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left">
                <tr className="border-b">
                  <th className="label-caps py-2 pr-4">Dataset</th>
                  <th className="label-caps py-2 pr-4">Period (UTC)</th>
                  <th className="label-caps py-2 pr-4 text-right">Events</th>
                  <th className="label-caps py-2 pr-4 text-right">Flagged</th>
                  <th className="label-caps py-2 text-right">Blocked</th>
                </tr>
              </thead>
              <tbody>
                {datasets.map((d) => (
                  <tr key={d.upload_id} className="border-b last:border-0">
                    <td className="py-2 pr-4">
                      <Link to={`/logs?upload=${d.upload_id}`} className="font-medium hover:underline">{d.filename}</Link>
                    </td>
                    <td className="py-2 pr-4 text-muted-foreground">
                      {d.first_event && d.last_event ? `${formatUtc(d.first_event)} – ${formatUtc(d.last_event)}` : '—'}
                    </td>
                    <td className="py-2 pr-4 text-right tabular-nums">{d.events.toLocaleString()}</td>
                    <td className="py-2 pr-4 text-right tabular-nums">
                      <Link to={`/logs?upload=${d.upload_id}&flagged=1`} className="hover:underline">{d.flagged.toLocaleString()}</Link>
                    </td>
                    <td className="py-2 text-right tabular-nums">
                      <Link to={`/logs?upload=${d.upload_id}&action=Blocked`} className="hover:underline">{d.blocked.toLocaleString()}</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
