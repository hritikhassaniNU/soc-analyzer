import { ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import { Fragment, useState } from 'react'
import { Link } from 'react-router'
import { type Detector, useSwitchDetector } from '@/api/rules'
import MultiSelect from '@/components/MultiSelect'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { disableWarning, LAYER_HELP, LAYER_LABELS } from '@/lib/detectors'
import { capitalize, formatDateTime, formatRelative } from '@/lib/format'
import { HttpError } from '@/lib/queryClient'
import { cn } from '@/lib/utils'


type Layer = Detector['layer']

/** An accessible on/off switch (a button with role="switch"). */
function Switch({ on, label, disabled, onChange }: { on: boolean; label: string; disabled: boolean; onChange: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange() }} // don't also expand the row
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-50',
        on ? 'bg-primary' : 'bg-muted-foreground/40',
      )}
    >
      <span className={cn('inline-block size-4 rounded-full bg-background transition-transform', on ? 'translate-x-4.5' : 'translate-x-0.5')} />
    </button>
  )
}

export default function DetectorTable({ detectors }: { detectors: Detector[] }) {
  const [names, setNames] = useState<string[]>([]) // empty = all (D99)
  const [types, setTypes] = useState<string[]>([])
  const [open, setOpen] = useState<string | null>(null)
  const switcher = useSwitchDetector()

  const maxHits = Math.max(0, ...detectors.map((d) => d.hits))
  const shown = detectors.filter((d) =>
    (types.length === 0 || types.includes(d.layer)) && (names.length === 0 || names.includes(d.kind)))

  function toggle(d: Detector) {
    // Switching off stops new scans from finding something: confirm, and say what.
    if (d.enabled && !window.confirm(disableWarning(d.name, d.summary))) return
    switcher.mutate({ kind: d.kind, enabled: !d.enabled })
  }

  const error = switcher.isError
    ? switcher.error instanceof HttpError && switcher.error.status !== 0 ? switcher.error.message : "Can't reach the server. Try again."
    : null

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-3">
        <MultiSelect label="Detectors" allLabel="All detectors" selected={names} onChange={setNames}
                     options={detectors.map((d) => ({ value: d.kind, label: d.name }))} />
        <MultiSelect label="Types" allLabel="All types" selected={types} onChange={setTypes}
                     options={(Object.keys(LAYER_LABELS) as Layer[]).map((l) => ({
                       value: l, label: LAYER_LABELS[l], count: detectors.filter((d) => d.layer === l).length }))} />
      </div>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}

      <div className="overflow-x-auto rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8" />
              <TableHead>Detector</TableHead>
              <TableHead>Type</TableHead>
              <TableHead title="The kind of evidence this detector adds to a case (several detectors can share one)">Evidence category</TableHead>
              <TableHead className="text-right" title="How strongly this kind of evidence counts toward a case's risk (score × weight)">Risk weight</TableHead>
              <TableHead className="pl-6">Hits</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead>Enabled</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shown.map((d) => {
              const expanded = open === d.kind
              return (
                <Fragment key={d.kind}>
                  <TableRow className={cn('cursor-pointer', !d.enabled && 'opacity-60')} onClick={() => setOpen(expanded ? null : d.kind)}>
                    <TableCell>
                      <button type="button" aria-expanded={expanded} aria-label={`${expanded ? 'Hide' : 'Show'} details for ${d.name}`}
                              className="text-muted-foreground" onClick={(e) => { e.stopPropagation(); setOpen(expanded ? null : d.kind) }}>
                        {expanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                      </button>
                    </TableCell>
                    <TableCell className="max-w-80 whitespace-normal">
                      <p className="font-semibold">{d.name}</p>
                      <p className="text-xs text-muted-foreground">{d.summary}</p>
                    </TableCell>
                    <TableCell>{LAYER_LABELS[d.layer]}</TableCell>
                    <TableCell className="whitespace-nowrap">{capitalize(d.category_label)}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {d.layer === 'ml' ? <span className="meta">Evidence only</span> : d.weight.toFixed(1)}
                    </TableCell>
                    <TableCell className="pl-6 tabular-nums">
                      {/* Number first, its bar right after (D118): the bar reads as Hits, not Risk weight.
                          Bar is relative to the most-firing detector. */}
                      <div className="flex items-center gap-2">
                        <span className="w-8 text-right">{d.hits.toLocaleString()}</span>
                        <div className="h-1.5 w-16 rounded-full bg-muted" aria-hidden>
                          <div className="h-1.5 rounded-full bg-[var(--series-1)]" style={{ width: `${maxHits ? (d.hits / maxHits) * 100 : 0}%` }} />
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {d.last_seen ? <time dateTime={d.last_seen} title={formatDateTime(d.last_seen)}>{formatRelative(d.last_seen)}</time> : 'Never'}
                    </TableCell>
                    <TableCell>
                      <Switch on={d.enabled} label={`${d.name} enabled`} disabled={switcher.isPending} onChange={() => toggle(d)} />
                    </TableCell>
                  </TableRow>
                  {expanded && (
                    <TableRow className="hover:bg-transparent">
                      <TableCell />
                      <TableCell colSpan={7} className="whitespace-normal">
                        <DetectorDetail d={d} />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              )
            })}
          </TableBody>
        </Table>
        {shown.length === 0 && <p className="p-4 text-sm text-muted-foreground">No detectors match.</p>}
      </div>
    </div>
  )
}

function DetectorDetail({ d }: { d: Detector }) {
  return (
    <div className="grid gap-6 py-2 text-sm md:grid-cols-2">
      <div className="flex flex-col gap-3">
        <div>
          <h3 className="subsection-title">How it decides</h3>
          <p className="text-xs text-muted-foreground">{LAYER_HELP[d.layer]}</p>
          <ul className="mt-1 ml-5 list-disc">{d.logic.map((line) => <li key={line}>{line}</li>)}</ul>
        </div>
        <div>
          <h3 className="subsection-title">Tuning</h3>
          <p className="text-muted-foreground">{d.tuning}</p>
        </div>
      </div>
      <div className="flex flex-col gap-3">
        <div>
          <h3 className="subsection-title">Known false positives</h3>
          <ul className="mt-1 ml-5 list-disc text-muted-foreground">{d.false_positives.map((fp) => <li key={fp}>{fp}</li>)}</ul>
        </div>
        {d.techniques.length > 0 && (
          <div>
            <h3 className="subsection-title">MITRE ATT&amp;CK</h3>
            <ul className="mt-1 flex flex-col gap-1">
              {d.techniques.map((t) => (
                <li key={t.id}>
                  <a href={t.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline-offset-2 hover:underline">
                    <span className="font-mono">{t.id}</span> {t.name} <ExternalLink className="size-3" aria-hidden />
                  </a>
                  <span className="text-muted-foreground">
                    {' '}· {t.tactic}
                    {t.approximate && ' · approximate fit'}
                    {t.supports && ' · supporting evidence, not detected by itself'}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3">
          {d.cases > 0 ? (
            <Link to={`/investigations?detector=${d.kind}`} className="font-medium underline-offset-2 hover:underline">
              View {d.cases} {d.cases === 1 ? 'case' : 'cases'} →
            </Link>
          ) : <span className="text-muted-foreground">No cases yet</span>}
          {d.changed_at && (
            <span className="text-xs text-muted-foreground">
              {d.enabled ? 'Switched on' : 'Switched off'} by {d.changed_by ?? 'a deleted account'},{' '}
              <time dateTime={d.changed_at} title={formatDateTime(d.changed_at)}>{formatRelative(d.changed_at)}</time>
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
