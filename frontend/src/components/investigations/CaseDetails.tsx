import { useRef } from 'react'
import { type CaseUpdate, type InvestigationDetail, useUpdateInvestigation } from '@/api/investigations'
import { ResolveDialog } from '@/components/investigations/CaseActions'
import { EntityChips } from '@/components/investigations/Labels'
import { formatDateTime, formatRelative, formatUtc } from '@/lib/format'
import { STATUS_LABELS, VERDICT_LABELS } from '@/lib/investigations'
import { HttpError } from '@/lib/queryClient'

// Inline field: looks like text until hovered/focused (label: value rows, like SOC case panels).
const FIELD = 'h-8 w-full rounded-md border border-transparent bg-transparent px-2 text-sm hover:border-input focus-visible:border-input disabled:opacity-60'

/** "Case details" side panel (D91): status, owner and verdict edited inline, plus the facts.
 *  The server enforces the rules (D67); choosing Resolved opens the resolve dialog (verdict first). */
export default function CaseDetails({ d }: { d: InvestigationDetail }) {
  const update = useUpdateInvestigation(d)
  const dialog = useRef<HTMLDialogElement>(null)
  const change = (c: CaseUpdate) => update.mutate(c)
  const error = update.isError
    ? update.error instanceof HttpError && update.error.status !== 0 ? update.error.message : "Can't reach the server. Try again."
    : null

  const rows: [string, React.ReactNode][] = [
    ['Status', (
      <select aria-label="Status" className={FIELD} value={d.status} disabled={update.isPending}
              onChange={(e) => (e.target.value === 'resolved' ? dialog.current?.showModal() : change({ status: e.target.value as 'open' | 'investigating' }))}>
        {Object.entries(STATUS_LABELS).map(([value, label]) => (
          <option key={value} value={value}>{value === 'resolved' && d.status !== 'resolved' ? 'Resolve…' : label}</option>
        ))}
      </select>
    )],
    ['Owner', (
      <select aria-label="Owner" className={FIELD} value={d.owner ?? ''} disabled={update.isPending}
              onChange={(e) => change({ owner: e.target.value || null })}>
        <option value="" disabled={d.status === 'investigating'}>Unassigned</option>
        {d.analysts.map((name) => <option key={name} value={name}>{name}</option>)}
      </select>
    )],
    ['Verdict', (
      <select aria-label="Verdict" className={FIELD} value={d.verdict ?? ''} disabled={update.isPending}
              onChange={(e) => change({ verdict: (e.target.value || null) as CaseUpdate['verdict'] })}>
        <option value="" disabled={d.status === 'resolved'}>—</option>
        {Object.entries(VERDICT_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
    )],
    ['Risk', <span className="block px-2 tabular-nums"><b>{d.risk}</b> · {d.signals} signal{d.signals === 1 ? '' : 's'} · {d.alerts} alert{d.alerts === 1 ? '' : 's'}</span>],
    ['Occurred', <span className="block px-2 whitespace-nowrap">{formatUtc(d.start_ts)}</span>],
    ['Updated', <time className="block px-2" dateTime={d.updated_at} title={formatDateTime(d.updated_at)}>{formatRelative(d.updated_at)}</time>],
  ]

  return (
    <aside aria-label="Case details" className="flex flex-col gap-3 rounded-xl border bg-card p-4 lg:sticky lg:top-20">
      <h2 className="label-caps">Case details</h2>
      <dl className="grid grid-cols-[5rem_1fr] items-center gap-x-2 gap-y-1 text-sm">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="min-w-0">{value}</dd>
          </div>
        ))}
      </dl>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <div className="border-t pt-3">
        <h3 className="label-caps mb-2">Entities</h3>
        <EntityChips entities={d.entities} />
      </div>
      <ResolveDialog d={d} dialog={dialog} />
    </aside>
  )
}
