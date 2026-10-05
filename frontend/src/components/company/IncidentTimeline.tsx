import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Dashboard } from '@/api/dashboard'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { PRIORITY_META, PRIORITY_ORDER, SEVERITY_COLORS } from '@/lib/incidents'

const AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 }
const day = new Intl.DateTimeFormat(undefined, { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' })
const label = (iso: string) => day.format(new Date(`${iso}T00:00:00Z`))

/** Incidents per day (by start, UTC), stacked by severity; worst on top of the stack is drawn last. */
export default function IncidentTimeline({ timeline }: { timeline: Dashboard['timeline'] }) {
  const [asTable, setAsTable] = useState(false)
  return (
    <Card>
      <CardHeader className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <CardTitle>Incidents over time</CardTitle>
          <CardDescription>Per day by start time (UTC), stacked by severity</CardDescription>
        </div>
        {timeline.length > 0 && (
          <Button variant="outline" size="sm" onClick={() => setAsTable((v) => !v)}>
            {asTable ? 'Show as chart' : 'Show as table'}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {timeline.length === 0 ? (
          <p className="text-sm text-muted-foreground">No incidents yet.</p>
        ) : asTable ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Day (UTC)</TableHead>
                {PRIORITY_ORDER.map((p) => <TableHead key={p} className="text-right">{PRIORITY_META[p].label}</TableHead>)}
              </TableRow>
            </TableHeader>
            <TableBody>
              {timeline.map((d) => (
                <TableRow key={d.day}>
                  <TableCell>{label(d.day)}</TableCell>
                  {PRIORITY_ORDER.map((p) => <TableCell key={p} className="text-right tabular-nums">{d[p]}</TableCell>)}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <>
            <div className="h-56">
              <ResponsiveContainer>
                <BarChart data={timeline} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--viz-grid)" />
                  <XAxis dataKey="day" tickFormatter={label} tick={AXIS_TICK} axisLine={{ stroke: 'var(--viz-axis)' }} tickLine={false} />
                  <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} />
                  <Tooltip
                    labelFormatter={(v) => label(String(v))}
                    contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--popover-foreground)' }}
                    cursor={{ fill: 'var(--muted)', opacity: 0.5 }}
                  />
                  {/* low at the bottom, critical on top; 2px surface gap between stacked segments */}
                  {[...PRIORITY_ORDER].reverse().map((p) => (
                    <Bar key={p} dataKey={p} name={PRIORITY_META[p].label} stackId="severity"
                         fill={SEVERITY_COLORS[p]} stroke="var(--card)" strokeWidth={2} isAnimationActive={false} />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </div>
            <ul className="mt-3 flex flex-wrap gap-4 text-xs text-muted-foreground">
              {PRIORITY_ORDER.map((p) => (
                <li key={p} className="flex items-center gap-1.5">
                  <span className="size-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[p] }} aria-hidden />
                  {PRIORITY_META[p].label}
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  )
}
