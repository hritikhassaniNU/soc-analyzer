import type { RulesCatalog } from '@/api/rules'
import { capitalize } from '@/lib/format'
import { PRIORITY_META } from '@/lib/incidents'

/** How findings become a case's risk: the correlation formula with the real numbers (D40). */
export default function ScoringPanel({ scoring }: { scoring: RulesCatalog['scoring'] }) {
  const pct = (x: number) => Math.round(x * 100)
  return (
    <div className="grid items-start gap-6 lg:grid-cols-2">
      <section className="flex flex-col gap-3 rounded-xl border bg-card p-6 text-sm">
        <h2 className="section-title">How a case's risk is computed</h2>
        <ol className="ml-5 list-decimal space-y-2">
          <li>Findings for the same user that start within {scoring.chain_hours} hours of each other become one case.</li>
          <li>Each finding's score (0–1) is multiplied by its evidence category's risk weight (table).</li>
          <li>
            Risk = the strongest weighted evidence category + {pct(scoring.corroboration_bonus)} for each other evidence category whose
            weighted score is at least {pct(scoring.corroboration_min)}, at most 100.
          </li>
          <li>
            Large uploads to approved storage ({scoring.approved_hosts.join(', ') || 'none configured'}) count
            {' '}{scoring.approved_weight}× (setting APPROVED_UPLOAD_HOSTS).
          </li>
          <li>Machine-learning findings are evidence only: they never change risk.</li>
        </ol>
        <p className="text-xs text-muted-foreground">
          A heuristic ranking for triage, not a probability of compromise.
        </p>
      </section>

      <div className="flex flex-col gap-6">
        <section className="flex flex-col gap-3 rounded-xl border bg-card p-6">
          <h2 className="section-title">Risk weight by evidence category</h2>
          <ul className="flex flex-col gap-2 text-sm">
            {scoring.weights.map((w) => (
              <li key={w.category} className="flex flex-col gap-1">
                <div className="flex justify-between">
                  <span>{capitalize(w.label)}</span>
                  <span className="font-semibold tabular-nums">{w.weight}</span>
                </div>
                <div className="h-2 rounded-full bg-muted">
                  <div className="h-2 rounded-full bg-[var(--series-1)]" style={{ width: `${w.weight * 100}%` }} />
                </div>
              </li>
            ))}
          </ul>
        </section>
        <section className="flex flex-col gap-3 rounded-xl border bg-card p-6">
          <h2 className="section-title">Severity from risk</h2>
          <ul className="flex flex-col gap-1.5 text-sm">
            {scoring.cutoffs.map((c) => {
              const { label, icon: Icon, iconClass } = PRIORITY_META[c.priority as keyof typeof PRIORITY_META]
              return (
                <li key={c.priority} className="flex items-center gap-2">
                  <Icon className={`size-4 ${iconClass}`} aria-hidden />
                  <span className="w-20 font-medium">{label}</span>
                  <span className="text-muted-foreground">risk ≥ {pct(c.min_score)}</span>
                </li>
              )
            })}
            <li className="flex items-center gap-2">
              {(() => { const { icon: Icon, iconClass } = PRIORITY_META.low; return <Icon className={`size-4 ${iconClass}`} aria-hidden /> })()}
              <span className="w-20 font-medium">{PRIORITY_META.low.label}</span>
              <span className="text-muted-foreground">anything lower</span>
            </li>
          </ul>
        </section>
      </div>
    </div>
  )
}
