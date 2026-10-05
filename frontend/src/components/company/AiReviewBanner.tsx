import { ArrowRight, Loader2, Sparkles, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useGenerateReview, useReview } from '@/api/dashboard'
import { useUsers } from '@/api/users'
import { ReviewCard } from '@/components/company/AiReview'
import RichText from '@/components/RichText'
import { Button } from '@/components/ui/button'

/** The AI review as one line under the KPIs (D130): its headline + "Read full review", which opens
 *  the full review in a side panel. Keeps the dashboard to numbers and charts first. */
export default function AiReviewBanner() {
  const review = useReview()
  const generate = useGenerateReview()
  const users = (useUsers('').data ?? []).map((u) => u.username)
  const [open, setOpen] = useState(false)
  const close = useCallback(() => setOpen(false), []) // stable: the panel's effect runs once
  const r = review.data

  return (
    <section aria-label="AI review" className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border bg-card px-4 py-3">
      <Sparkles className="size-4 shrink-0 text-primary" aria-hidden />
      <span className="label-caps">AI review</span>
      <p className="min-w-0 flex-1 text-sm font-medium">
        {generate.isPending ? (
          <span className="inline-flex items-center gap-2 font-normal text-muted-foreground" aria-live="polite">
            <Loader2 className="size-4 animate-spin" aria-hidden /> Generating the analysis… (up to a minute)
          </span>
        ) : r ? (
          <>
            <RichText text={r.headline || r.summary.split('. ')[0]} users={users} />
            {r.stale && <span className="ml-2 rounded-md bg-muted px-1.5 py-0.5 text-xs font-normal text-muted-foreground">Outdated</span>}
          </>
        ) : review.isSuccess ? (
          <span className="font-normal text-muted-foreground">No review yet.</span>
        ) : null}
      </p>
      {r ? (
        <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>Read full review <ArrowRight /></Button>
      ) : review.isSuccess && !generate.isPending && (
        <Button size="sm" onClick={() => generate.mutate()}><Sparkles /> Generate analysis</Button>
      )}
      {open && <ReviewPanel onClose={close} review={review} generate={generate} />}
    </section>
  )
}

/** Right-hand side panel: Escape or the backdrop closes it; focus moves in and returns after. */
function ReviewPanel({ onClose, review, generate }: {
  onClose: () => void
  review: ReturnType<typeof useReview>
  generate: ReturnType<typeof useGenerateReview>
}) {
  const panel = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null
    panel.current?.focus()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('keydown', onKey); before?.focus() }
  }, [onClose])
  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden />
      <div ref={panel} role="dialog" aria-modal="true" aria-label="AI review" tabIndex={-1}
           className="relative flex h-full w-full max-w-xl flex-col overflow-y-auto border-l bg-background p-4 outline-none">
        <Button variant="ghost" size="icon" className="absolute top-5 right-5 z-10" onClick={onClose} aria-label="Close"><X /></Button>
        <ReviewCard title="AI review" review={review} generate={generate} stacked
                    empty="No review yet. It summarizes who needs attention first, the patterns seen and what to do next." />
      </div>
    </div>,
    document.body,
  )
}
