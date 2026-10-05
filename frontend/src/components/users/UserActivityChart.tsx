import { useState } from 'react'
import { CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { UserProfile } from '@/api/users'
import { Button } from '@/components/ui/button'
import { midnightTicks } from '@/lib/activityAxis'
import { PRIORITY_META, SEVERITY_COLORS } from '@/lib/incidents'

const AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 }
const day = new Intl.DateTimeFormat(undefined, { day: 'numeric', weekday: 'short', timeZone: 'UTC' })
const full = new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })
const SERIES = [
  { key: 'blocked', label: 'Blocked', color: 'var(--series-2)' },
  { key: 'flagged', label: 'Flagged by rules', color: 'var(--series-3)' },
] as const

/** This user's blocked and rule-flagged requests per time bucket (D92), with each incident's window
 *  shaded in its severity color. Every series is named in the legend and tooltip, and the same
 *  numbers are available as a table (never color alone). */
export default function UserActivityChart({ activity }: { activity: UserProfile['activity'] }) {
  const [asTable, setAsTable] = useState(false)
  const data = activity.points.map((p) => ({ ...p, t: Date.parse(p.ts) }))
  if (data.length === 0) return null
  const first = data[0].t
  const last = data[data.length - 1].t
  const per = activity.bucket_hours === 1 ? 'hour' : activity.bucket_hours === 24 ? 'day' : `${activity.bucket_hours} hours`

  return (
    <section className="flex flex-col gap-3 rounded-xl border bg-card p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <h2 className="section-title">Blocked and flagged per {per}</h2>
          {SERIES.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground">
              <span className="h-0.5 w-4 rounded" style={{ background: s.color }} aria-hidden /> {s.label}
            </span>
          ))}
        </div>
        <Button variant="outline" size="sm" onClick={() => setAsTable((v) => !v)}>{asTable ? 'Show as chart' : 'Show as table'}</Button>
      </div>

      {asTable ? (
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left">
                <th className="label-caps py-2">Time (UTC)</th>
                <th className="label-caps py-2 text-right">Blocked</th>
                <th className="label-caps py-2 text-right">Flagged</th>
                <th className="label-caps py-2 text-right">All events</th>
              </tr>
            </thead>
            <tbody>
              {data.filter((p) => p.events > 0).map((p) => (
                <tr key={p.t} className="border-b last:border-0">
                  <td className="py-1.5">{full.format(p.t)}</td>
                  <td className="py-1.5 text-right tabular-nums">{p.blocked}</td>
                  <td className="py-1.5 text-right tabular-nums">{p.flagged}</td>
                  <td className="py-1.5 text-right tabular-nums">{p.events.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-56" role="img" aria-label={`Blocked and flagged requests per ${per}, UTC, with incident windows shaded`}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} stroke="var(--viz-grid)" />
              {activity.incidents.map((w) => (
                <ReferenceArea key={w.case_id} x1={Date.parse(w.start)}
                               x2={Math.max(Date.parse(w.end), Date.parse(w.start) + 3_600_000)}
                               fill={SEVERITY_COLORS[w.priority]} fillOpacity={0.14} stroke="none" ifOverflow="hidden" />
              ))}
              <XAxis dataKey="t" type="number" scale="time" domain={[first, last]} ticks={midnightTicks(first, last)}
                     tickFormatter={(t) => day.format(t)} tick={AXIS_TICK} axisLine={{ stroke: 'var(--viz-axis)' }} tickLine={false} />
              <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} />
              <Tooltip
                labelFormatter={(t) => `${full.format(Number(t))} UTC`}
                formatter={(value, name) => [value, SERIES.find((s) => s.key === name)?.label ?? name]}
                contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13 }}
                labelStyle={{ color: 'var(--foreground)' }}
              />
              {SERIES.map((s) => (
                <Line key={s.key} dataKey={s.key} name={s.key} stroke={s.color} strokeWidth={2} dot={false} isAnimationActive={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      {activity.incidents.length > 0 && (
        <p className="meta">
          Shaded: {activity.incidents.length} incident window{activity.incidents.length === 1 ? '' : 's'} in severity color
          ({[...new Set(activity.incidents.map((w) => PRIORITY_META[w.priority].label))].join(', ')}).
        </p>
      )}
    </section>
  )
}
