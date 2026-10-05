import { Cell, Pie, PieChart, ResponsiveContainer } from 'recharts'
import type { Dashboard } from '@/api/dashboard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { capitalize, formatPercent } from '@/lib/format'
import { PRIORITY_META, PRIORITY_ORDER, SEVERITY_COLORS } from '@/lib/incidents'


/** Two views of the same incidents. Severity (4 parts of a whole): a donut. Category (up to
 *  7 kinds, compared by size): horizontal bars, because many thin slices are hard to compare. */
export default function RiskBreakdown({ severity, categories }: Pick<Dashboard, 'severity' | 'categories'>) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk breakdown</CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="severity">
          <TabsList>
            <TabsTrigger value="severity">Severity</TabsTrigger>
            <TabsTrigger value="category">Evidence category</TabsTrigger>
          </TabsList>
          <TabsContent value="severity"><SeverityDonut severity={severity} /></TabsContent>
          <TabsContent value="category"><CategoryBars categories={categories} /></TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}

function SeverityDonut({ severity }: { severity: Record<string, number> }) {
  const total = PRIORITY_ORDER.reduce((sum, p) => sum + (severity[p] ?? 0), 0)
  if (total === 0) return <p className="py-6 text-sm text-muted-foreground">No incidents yet.</p>
  const data = PRIORITY_ORDER.map((p) => ({ key: p, value: severity[p] ?? 0 })).filter((d) => d.value > 0)
  const summary = PRIORITY_ORDER.map((p) => `${severity[p] ?? 0} ${p}`).join(', ')
  return (
    <div className="flex flex-wrap items-center gap-4 pt-2">
      <div className="relative size-36 shrink-0" role="img" aria-label={`Incidents by severity: ${summary}`}>
        <ResponsiveContainer>
          <PieChart>
            {/* stroke = the card surface: a 2px gap between slices */}
            <Pie data={data} dataKey="value" nameKey="key" innerRadius="62%" outerRadius="100%"
                 stroke="var(--card)" strokeWidth={2} isAnimationActive={false}>
              {data.map((d) => <Cell key={d.key} fill={SEVERITY_COLORS[d.key]} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="metric">{total}</span>
          <span className="text-xs text-muted-foreground">incidents</span>
        </div>
      </div>
      <ul className="flex min-w-36 flex-1 flex-col gap-2 text-sm">
        {PRIORITY_ORDER.map((p) => {
          const { label, icon: Icon, iconClass } = PRIORITY_META[p]
          const n = severity[p] ?? 0
          return (
            <li key={p} className="flex items-center gap-2">
              <span className="size-2.5 shrink-0 rounded-sm" style={{ background: SEVERITY_COLORS[p] }} aria-hidden />
              <Icon className={`size-4 shrink-0 ${iconClass}`} aria-hidden />
              <span className="flex-1">{label}</span>
              <span className="tabular-nums font-medium">{n}</span>
              <span className="w-12 text-right tabular-nums text-muted-foreground">{formatPercent(n / total)}</span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function CategoryBars({ categories }: { categories: Dashboard['categories'] }) {
  if (categories.length === 0) {
    return <p className="py-6 text-sm text-muted-foreground">No medium, high or critical incidents.</p>
  }
  const max = Math.max(...categories.map((c) => c.incidents))
  return (
    <div className="flex flex-col gap-3 pt-2">
      <p className="text-xs text-muted-foreground">Medium or higher incidents, by their strongest evidence category</p>
      <ul className="flex flex-col gap-2.5">
        {categories.map((c) => (
          <li key={c.category} className="flex flex-col gap-1 text-sm">
            <div className="flex justify-between gap-3">
              <span>{capitalize(c.label)}</span>
              <span className="tabular-nums font-medium">{c.incidents}</span>
            </div>
            <div className="h-2 rounded-full bg-muted">
              <div className="h-2 rounded-full" style={{ width: `${(c.incidents / max) * 100}%`, background: 'var(--series-1)' }} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
