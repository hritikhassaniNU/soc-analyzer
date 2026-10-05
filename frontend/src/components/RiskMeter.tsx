import type { Investigation } from '@/api/investigations'
import { SEVERITY_COLORS } from '@/lib/incidents'

/** Risk 0-100 as a short bar in the severity color + the number (D127): the one way risk is shown
 *  everywhere (queue, users, dashboard), never the raw 0-1 score. */
export default function RiskMeter({ risk, priority, width = 'w-16' }: {
  risk: number; priority: Investigation['priority']; width?: string
}) {
  return (
    <span className="inline-flex items-center gap-2" title={`Risk ${risk} of 100 (heuristic ranking, not a probability)`}>
      <span className={`h-1.5 ${width} rounded-full bg-muted`} aria-hidden>
        <span className="block h-1.5 rounded-full" style={{ width: `${risk}%`, background: SEVERITY_COLORS[priority] }} />
      </span>
      <span className="w-8 text-right font-semibold tabular-nums">{risk}</span>
    </span>
  )
}
