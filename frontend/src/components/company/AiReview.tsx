import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'
import { History, Loader2, RefreshCw, Sparkles } from 'lucide-react'
import type { components } from '@/api/schema'
import { Button } from '@/components/ui/button'
import { useUsers } from '@/api/users'
import RichText from '@/components/RichText'
import { SourceLabel } from '@/components/SourceLabel'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PRIORITY_META } from '@/lib/incidents'

type Review = components['schemas']['ReviewOut']

/** Shared by the company review (dashboard) and the per-user review (user profile). */
export function ReviewCard({ title, review, generate, empty, stacked = false }: {
  title: string
  stacked?: boolean // narrow container (side panel): findings and actions one under the other
  review: UseQueryResult<Review | null | undefined>
  generate: UseMutationResult<Review, Error, void>
  empty: string
}) {
  const r = review.data

  return (
    <Card>
      <CardHeader className={stacked ? 'flex flex-wrap items-center gap-2 pr-12' : 'flex flex-wrap items-center justify-between gap-2'}>
        <CardTitle>{title}</CardTitle>
        {r && (
          // Source label and "Generated … by …" line removed at the user's request (D78).
          <Button variant="outline" size="sm" onClick={() => generate.mutate()} disabled={generate.isPending}>
            <RefreshCw /> Regenerate analysis
          </Button>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {review.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
        {review.isError && <p className="text-sm text-destructive">Can't load the review.</p>}

        {generate.isPending ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground" aria-live="polite">
            <Loader2 className="size-4 animate-spin" aria-hidden /> Generating the analysis… (up to a minute)
          </p>
        ) : r ? (
          <>
            {r.stale && (
              // Neutral (priority colors are reserved for severity); the icon + words carry it.
              <p role="status" className="flex items-center gap-2 rounded-md border bg-muted/60 px-3 py-2 text-sm">
                <History className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                New scans finished since this analysis. Regenerate the analysis to include them.
              </p>
            )}
            <Analysis r={r} stacked={stacked} />
            {/* "AI-generated" only when Claude wrote it; template text has no footer (D138). */}
            {r.source === 'ai' && <p className="meta"><SourceLabel ai /></p>}
          </>
        ) : (
          review.isSuccess && (
            <div className="flex flex-col items-start gap-3">
              <p className="text-sm text-muted-foreground">{empty}</p>
              <Button size="sm" onClick={() => generate.mutate()}>
                <Sparkles /> Generate analysis
              </Button>
            </div>
          )
        )}
        {generate.isError && <p className="text-sm text-destructive">Couldn't write the analysis. Try again.</p>}
      </CardContent>
    </Card>
  )
}

/** Headline, overview, key findings (severity icon + sentence) and recommended actions (D80).
 *  Reviews written before the sections existed show their paragraph only. */
function Analysis({ r, stacked }: { r: Review; stacked: boolean }) {
  const users = (useUsers('').data ?? []).map((u) => u.username) // known users become profile links
  const findings = r.key_findings.slice(0, 3) // older reviews may hold 5; keep the card short (D94)
  const actions = r.actions.slice(0, 3)
  return (
    <div className="flex flex-col gap-4">
      {r.headline && <p className="text-base leading-snug font-semibold"><RichText text={r.headline} users={users} /></p>}
      <p className="max-w-[75ch] text-sm leading-relaxed text-muted-foreground"><RichText text={r.summary} users={users} /></p>
      {(findings.length > 0 || actions.length > 0) && (
        <div className={stacked ? 'grid gap-3' : 'grid gap-3 lg:grid-cols-2'}>
          <section aria-labelledby="key-findings" className="rounded-lg border bg-muted/30 p-4">
            <h3 id="key-findings" className="label-caps mb-3">Key findings</h3>
            <ul className="flex flex-col gap-2.5">
              {findings.map((f, n) => {
                const { label, icon: Icon, iconClass } = PRIORITY_META[f.priority]
                return (
                  <li key={n} className="flex gap-2.5 text-sm">
                    <Icon className={`mt-0.5 size-4 shrink-0 ${iconClass}`} aria-label={label} />
                    <span><RichText text={f.text} users={users} /></span>
                  </li>
                )
              })}
            </ul>
          </section>
          {actions.length > 0 && (
            <section aria-labelledby="actions" className="rounded-lg border bg-muted/30 p-4">
              <h3 id="actions" className="label-caps mb-3">Recommended actions</h3>
              <ol className="flex flex-col gap-2.5">
                {actions.map((a, n) => (
                  <li key={n} className="flex gap-2.5 text-sm">
                    <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground tabular-nums" aria-hidden>
                      {n + 1}
                    </span>
                    <span><RichText text={a} users={users} /></span>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </div>
      )}
    </div>
  )
}
