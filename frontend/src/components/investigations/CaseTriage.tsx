import { Search, Sparkles } from 'lucide-react'
import { Link } from 'react-router'
import type { InvestigationDetail } from '@/api/investigations'
import { Button } from '@/components/ui/button'
import { caseSearchParams } from '@/lib/eventFilters'
import { AI_VERDICT_LABELS } from '@/lib/investigations'
import { cn } from '@/lib/utils'

/** The AI's triage suggestion (D135): verdict + confidence in words + the deciding evidence.
 *  Only shown when Claude wrote the analysis; the analyst always decides. */
export function AiAssessment({ d }: { d: InvestigationDetail }) {
  const a = d.ai_assessment
  if (!a) return null
  return (
    // Neutral card: severity colors stay reserved for severity; the words carry the verdict.
    <section aria-label="AI assessment" className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded-xl border bg-card px-4 py-3">
      <Sparkles className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
      <p className="min-w-0 flex-1 text-sm">
        <span className="label-caps mr-2">AI assessment</span>
        <span className="font-semibold">{AI_VERDICT_LABELS[a.verdict]}</span>
        <span className="text-muted-foreground"> · {a.confidence} confidence</span>
        {/* Model-written: plain text. */}
        <span className="block text-muted-foreground">{a.reason}</span>
      </p>
      <span className="meta self-center">Suggestion · you decide</span>
    </section>
  )
}

/** Next-step searches as buttons that open Logs already filtered (D135). The filters come from the
 *  backend's menu; the AI only picked and labeled them. */
export function CaseSearches({ d, className }: { d: InvestigationDetail; className?: string }) {
  if (d.searches.length === 0) return null
  return (
    <section aria-labelledby={`searches-${d.id}`} className={cn('flex flex-col gap-2', className)}>
      <h3 id={`searches-${d.id}`} className="label-caps">Investigate next</h3>
      <div className="flex flex-wrap gap-2">
        {d.searches.map((s) => (
          <Button key={s.id} asChild variant="outline" size="sm">
            <Link to={{ pathname: '/logs', search: caseSearchParams(d.upload_id, s).toString() }}>
              <Search /> {s.label}
            </Link>
          </Button>
        ))}
      </div>
    </section>
  )
}
