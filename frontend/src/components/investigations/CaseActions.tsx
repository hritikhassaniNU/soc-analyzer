import { Play, RotateCcw, ScrollText, ShieldCheck, UserCheck } from 'lucide-react'
import { useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { useMe } from '@/api/auth'
import { type InvestigationDetail, useAddNote, useUpdateInvestigation } from '@/api/investigations'
import { Button } from '@/components/ui/button'
import { drillDownParams } from '@/lib/eventFilters'
import { AI_VERDICT_TO_CASE, NOTE_MAX_CHARS, VERDICT_LABELS } from '@/lib/investigations'
import { HttpError } from '@/lib/queryClient'

type Verdict = keyof typeof VERDICT_LABELS
const message = (e: unknown) => (e instanceof HttpError && e.status !== 0 ? e.message : "Can't reach the server. Try again.")

/** Logs filtered to the lines that contributed to the case (D117). */
function evidenceParams(d: InvestigationDetail): URLSearchParams {
  const user = d.entities.find((e) => e.type === 'user')?.name ?? ''
  const params = drillDownParams(d.upload_id, user, d.start_ts, d.end_ts)
  params.set('anomalous', '1')
  return params
}

/** Header actions (D91): Assign to me, View evidence events, and ONE primary action that follows the
 *  workflow: Open → "Start investigating", Investigating → "Resolve…", Resolved → "Reopen". */
export default function CaseActions({ d }: { d: InvestigationDetail }) {
  const me = useMe().data?.username
  const update = useUpdateInvestigation(d)
  const dialog = useRef<HTMLDialogElement>(null)

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex flex-wrap justify-end gap-2">
        {me && d.owner !== me && d.status !== 'resolved' && (
          <Button variant="outline" size="sm" disabled={update.isPending} onClick={() => update.mutate({ owner: me })}>
            <UserCheck /> Assign to me
          </Button>
        )}
        <Button asChild variant="outline" size="sm">
          {/* Only the lines that contributed (D117): this user, this window, Anomalies only (a rule match
              or inside one of the findings' windows). "All events" on Logs shows the surrounding context. */}
          <Link to={{ pathname: '/logs', search: evidenceParams(d).toString() }} title="Events that contributed to this case">
            <ScrollText /> View evidence events
          </Link>
        </Button>
        {d.status === 'open' && (
          <Button size="sm" disabled={update.isPending} onClick={() => update.mutate({ status: 'investigating' })}>
            <Play /> Start investigating
          </Button>
        )}
        {d.status === 'investigating' && (
          <Button size="sm" onClick={() => dialog.current?.showModal()}><ShieldCheck /> Resolve…</Button>
        )}
        {d.status === 'resolved' && (
          <Button size="sm" variant="outline" disabled={update.isPending} onClick={() => update.mutate({ status: 'open' })}>
            <RotateCcw /> Reopen
          </Button>
        )}
      </div>
      {update.isError && <p role="alert" className="text-sm text-destructive">{message(update.error)}</p>}
      <ResolveDialog d={d} dialog={dialog} />
    </div>
  )
}

/** Resolve in one step: verdict (required) + optional note. A native <dialog>: focus stays inside,
 *  Escape closes it. Also opened from the Case details status field. */
export function ResolveDialog({ d, dialog }: { d: InvestigationDetail; dialog: React.RefObject<HTMLDialogElement | null> }) {
  const update = useUpdateInvestigation(d)
  const addNote = useAddNote(d.id)
  // Pre-selected (D135): the case's own verdict, else the AI's suggestion (the analyst can change it).
  const suggested = d.ai_assessment ? AI_VERDICT_TO_CASE[d.ai_assessment.verdict] : null
  const [verdict, setVerdict] = useState<Verdict | ''>((d.verdict as Verdict | null) ?? suggested ?? '')
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!verdict) return setError('Choose a verdict to resolve the case.')
    setError(null)
    try {
      await update.mutateAsync({ status: 'resolved', verdict })
      if (note.trim()) await addNote.mutateAsync(note.trim())
      setNote('')
      dialog.current?.close()
    } catch (e) {
      setError(message(e))
    }
  }

  return (
    <dialog ref={dialog} aria-labelledby={`resolve-${d.id}`}
            className="m-auto w-[min(28rem,calc(100vw-2rem))] rounded-xl border bg-popover p-0 text-popover-foreground shadow-xl backdrop:bg-black/60">
      <form onSubmit={submit} className="flex flex-col gap-4 p-5">
        <h2 id={`resolve-${d.id}`} className="section-title">Resolve <span className="tech">{d.number}</span></h2>
        <fieldset className="flex flex-col gap-2">
          <legend className="label-caps mb-1">Verdict</legend>
          {(Object.keys(VERDICT_LABELS) as Verdict[]).map((v) => (
            <label key={v} className="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm has-[:checked]:border-primary has-[:checked]:bg-primary/10">
              <input type="radio" name="verdict" value={v} checked={verdict === v} onChange={() => setVerdict(v)} className="accent-[var(--primary)]" />
              {VERDICT_LABELS[v]}
              {!d.verdict && v === suggested && <span className="ml-auto text-xs text-muted-foreground">AI suggestion</span>}
            </label>
          ))}
        </fieldset>
        <label className="flex flex-col gap-1.5 text-sm">
          <span className="label-caps">Note (optional)</span>
          <textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={NOTE_MAX_CHARS} rows={3}
                    placeholder="What did you find? (saved to the case notes)"
                    className="rounded-lg border border-input bg-transparent px-3 py-2 text-sm dark:bg-input/30" />
        </label>
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => dialog.current?.close()}>Cancel</Button>
          <Button type="submit" disabled={update.isPending || addNote.isPending}>Resolve</Button>
        </div>
      </form>
    </dialog>
  )
}
