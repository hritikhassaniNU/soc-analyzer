import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { UserListItem } from '@/api/users'
import { PRIORITY_META, SEVERITY_COLORS } from '@/lib/incidents'
import { severityOfUser, USER_SEVERITIES, type UserSeverity } from '@/lib/usersList'
import { cn } from '@/lib/utils'
import ChartTooltip from '@/components/charts/ChartTooltip'

const AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 }
const META: Record<UserSeverity, { label: string; color: string }> = {
  critical: { label: PRIORITY_META.critical.label, color: SEVERITY_COLORS.critical },
  high: { label: PRIORITY_META.high.label, color: SEVERITY_COLORS.high },
  medium: { label: PRIORITY_META.medium.label, color: SEVERITY_COLORS.medium },
  low: { label: PRIORITY_META.low.label, color: SEVERITY_COLORS.low },
  none: { label: 'No open risk', color: 'var(--viz-axis)' },
}
// Users with open risk are drawn by default (D121): a gray 'no risk' segment dominated every bar.
// 'No open risk' is drawn only when that severity is picked in the filter (D128).
const AT_RISK = ['critical', 'high', 'medium', 'low'] as const
const RANK: Record<UserSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 }

/** Users per department stacked by their severity (D121): where risk is concentrated. Follows every
 *  filter except department; clicking a department bar or a legend entry filters the table. */
export default function RiskByDepartment({ users, departments, severities, onToggleDepartment, onToggleSeverity }: {
  users: UserListItem[]; departments: readonly string[]; severities: readonly UserSeverity[]
  onToggleDepartment: (d: string) => void; onToggleSeverity: (s: UserSeverity) => void
}) {
  const byDept = new Map<string, Record<UserSeverity, number>>()
  for (const u of users) {
    if (!u.department) continue
    const row = byDept.get(u.department) ?? { critical: 0, high: 0, medium: 0, low: 0, none: 0 }
    row[severityOfUser(u)] += 1
    byDept.set(u.department, row)
  }
  if (byDept.size === 0) return null
  const drawn: readonly UserSeverity[] = severities.includes('none') ? USER_SEVERITIES : AT_RISK
  // Riskiest department first: worst severity weighted, then size.
  const score = (r: Record<UserSeverity, number>) => USER_SEVERITIES.reduce((sum, s) => sum + r[s] * 10 ** RANK[s], 0)
  const data = [...byDept.entries()].sort((a, b) => score(b[1]) - score(a[1])).map(([department, r]) => ({ department, ...r, total: USER_SEVERITIES.reduce((n, s) => n + r[s], 0), atRisk: AT_RISK.reduce((n, s) => n + r[s], 0) }))
  return (
    <section className="rounded-xl border bg-card p-4">
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1">
        <h2 className="label-caps mr-2">{drawn.includes('none') ? 'Users by department' : 'Users at risk by department'}</h2>
        {USER_SEVERITIES.map((s) => (
          <button key={s} type="button" aria-pressed={severities.includes(s)} onClick={() => onToggleSeverity(s)}
                  title={severities.includes(s) ? `Remove the ${META[s].label} filter` : `Show only ${META[s].label}`}
                  className={cn('inline-flex items-center gap-1.5 rounded px-1 text-xs text-muted-foreground hover:text-foreground',
                    severities.includes(s) && 'font-medium text-foreground',
                    severities.length > 0 && !severities.includes(s) && 'opacity-40')}>
            <span className="size-2.5 rounded-sm" style={{ background: META[s].color }} aria-hidden /> {META[s].label}
          </button>
        ))}
      </div>
      <div style={{ height: data.length * 30 + 28 }} role="img" aria-label="Users with open risk per department, by severity, out of each department's users">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 8 }} barCategoryGap={6}
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => {
                      const d = (e as { activeLabel?: unknown } | null)?.activeLabel
                      if (typeof d === 'string') onToggleDepartment(d)
                    }}>
            <CartesianGrid horizontal={false} stroke="var(--viz-grid)" />
            <XAxis type="number" allowDecimals={false} tick={AXIS_TICK} axisLine={{ stroke: 'var(--viz-axis)' }} tickLine={false} />
            <YAxis type="category" dataKey="department" width={96} axisLine={false} tickLine={false}
                   tick={(props: { x?: number | string; y?: number | string; payload: { value: string } }) => (
                     <text x={props.x} y={props.y} dy={4} textAnchor="end" fontSize={12}
                           fill={departments.includes(props.payload.value) ? 'var(--foreground)' : 'var(--muted-foreground)'}
                           fontWeight={departments.includes(props.payload.value) ? 600 : 400}>{props.payload.value}</text>
                   )} />
            {/* Right-hand labels: at-risk users out of everyone in the department. */}
            <YAxis yAxisId="totals" orientation="right" type="category" dataKey="department" width={96} axisLine={false} tickLine={false}
                   tick={AXIS_TICK} tickFormatter={(d) => { const r = data.find((x) => x.department === d); return r ? `${r.atRisk} of ${r.total} users` : '' }} />
            <Tooltip cursor={{ fill: 'var(--muted)', opacity: 0.4 }}
                     content={<ChartTooltip hideZero title={(d) => (drawn.includes('none') ? `${d} users` : `${d}: users with open risk`)} names={(k) => META[k as UserSeverity]?.label ?? k}
                                            hint={(d) => (departments.includes(String(d)) ? `Click to remove the ${d} filter` : `Click to show only ${d}`)} />} />
            {drawn.map((s) => (
              <Bar key={s} dataKey={s} stackId="u" fill={META[s].color} isAnimationActive={false}
                   stroke="var(--card)" strokeWidth={1} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}
