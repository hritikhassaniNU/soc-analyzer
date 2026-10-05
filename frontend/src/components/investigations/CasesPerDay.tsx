import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Investigation } from '@/api/investigations'
import { cn } from '@/lib/utils'
import ChartTooltip from '@/components/charts/ChartTooltip'
import { PRIORITY_META, PRIORITY_ORDER, SEVERITY_COLORS } from '@/lib/incidents'

const AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 }
const dayLabel = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })

/** Cases per day (by when they occurred, UTC), stacked by severity, for the CURRENT filters.
 *  Clicking a day filters the queue to it. Legend names every color (never color alone). */
export default function CasesPerDay({ cases, selected, onSelect, severities, onToggleSeverity }: {
  cases: Investigation[]; selected: string | null; onSelect: (day: string | null) => void
  severities: readonly Investigation['priority'][]; onToggleSeverity: (p: Investigation['priority']) => void
}) {
  const byDay = new Map<string, Record<string, number>>()
  for (const c of cases) {
    const day = c.start_ts.slice(0, 10)
    const row = byDay.get(day) ?? Object.fromEntries(PRIORITY_ORDER.map((p) => [p, 0]))
    row[c.priority] += 1
    byDay.set(day, row)
  }
  if (byDay.size === 0) return null
  // Gap-fill: quiet days show as empty, not missing.
  const days = [...byDay.keys()].sort()
  const data = []
  for (let t = Date.parse(`${days[0]}T00:00:00Z`); t <= Date.parse(`${days[days.length - 1]}T00:00:00Z`); t += 86_400_000) {
    const day = new Date(t).toISOString().slice(0, 10)
    data.push({ day, ...(byDay.get(day) ?? Object.fromEntries(PRIORITY_ORDER.map((p) => [p, 0]))) })
  }
  return (
    <section className="rounded-xl border bg-card p-4">
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1">
        <h2 className="label-caps">Cases per day (UTC)</h2>
        {PRIORITY_ORDER.map((p) => (
          // Legend = severity filter: same URL state as the Severity dropdown.
          <button key={p} type="button" aria-pressed={severities.includes(p)} onClick={() => onToggleSeverity(p)}
                  title={severities.includes(p) ? `Remove the ${PRIORITY_META[p].label} filter` : `Show only ${PRIORITY_META[p].label}`}
                  className={cn('inline-flex items-center gap-1.5 rounded px-1 text-xs text-muted-foreground hover:text-foreground',
                    severities.includes(p) && 'font-medium text-foreground',
                    severities.length > 0 && !severities.includes(p) && 'opacity-40')}>
            <span className="size-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[p] }} aria-hidden /> {PRIORITY_META[p].label}
          </button>
        ))}
      </div>
      <div className="h-36" role="img" aria-label="Cases per day by severity for the current filters">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -24 }}
                    onClick={(e) => {
                      const day = (e as { activeLabel?: unknown } | null)?.activeLabel
                      if (typeof day === 'string') onSelect(day === selected ? null : day)
                    }} style={{ cursor: 'pointer' }}>
            <CartesianGrid vertical={false} stroke="var(--viz-grid)" />
            <XAxis dataKey="day" tickFormatter={(d) => dayLabel.format(new Date(`${d}T00:00:00Z`))} tick={AXIS_TICK}
                   axisLine={{ stroke: 'var(--viz-axis)' }} tickLine={false} minTickGap={16} />
            <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} />
            <Tooltip cursor={{ fill: 'var(--muted)', opacity: 0.4 }}
                     content={<ChartTooltip hideZero reverse title={(d) => dayLabel.format(new Date(`${d}T00:00:00Z`))}
                                            names={(k) => PRIORITY_META[k as keyof typeof PRIORITY_META]?.label ?? k}
                                            hint={(d) => (d === selected ? 'Click to show all days' : 'Click to show only this day')} />} />
            {[...PRIORITY_ORDER].reverse().map((p) => (
              <Bar key={p} dataKey={p} stackId="s" fill={SEVERITY_COLORS[p]} isAnimationActive={false}
                   fillOpacity={selected ? 0.35 : 1} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}
