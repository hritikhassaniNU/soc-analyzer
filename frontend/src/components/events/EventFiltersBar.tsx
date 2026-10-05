import { Search, X } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { type EventFilters, useDatasetBounds } from '@/api/events'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import MultiSelect from '@/components/MultiSelect'
import { inputFromUtc, SOURCE_VALUES, timePresets, type TimePreset, utcFromInput } from '@/lib/eventFilters'
import { formatUtc } from '@/lib/format'
import { RULE_LABELS } from '@/lib/rules'

const SOURCE_LABELS: Record<(typeof SOURCE_VALUES)[number], string> = {
  ...Object.fromEntries(Object.entries(RULE_LABELS).map(([k, v]) => [`rule:${k}`, `Rule: ${v}`])),
  'window:stat': 'Statistical finding window',
  'window:ml': 'Machine-learning finding window',
  'window:ai': 'AI finding (suspicious domain)',
} as Record<(typeof SOURCE_VALUES)[number], string>
import { cn } from '@/lib/utils'

const SELECT = 'h-9 rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30'

/**
 * Filter bar, like a SOC log search: one search box (user, IP, host, category, device),
 * a time range relative to the dataset's own dates, detection source, action and
 * "anomaly only". Dropdowns and toggles apply at once; the search applies on Enter. Exact filters
 * from drill-down links (user, host, category) show as removable chips. Remounted (via `key`)
 * when the URL's filters change, so every control shows the active filters.
 */
export default function EventFiltersBar({ uploadId, filters, onApply }: {
  uploadId: number
  filters: EventFilters
  onApply: (filters: EventFilters) => void
}) {
  const [search, setSearch] = useState(filters.q ?? '')
  const bounds = useDatasetBounds(uploadId).data
  // Presets are relative to now: a preset is "active" when its length matches the URL range and
  // it ends around now (a reload a minute later still shows "Last 3 days").
  const presets = timePresets()
  const span = filters.start && filters.end ? Date.parse(filters.end) - Date.parse(filters.start) : null
  const activePreset = (Object.keys(presets) as TimePreset[]).find((p) =>
    span === Date.parse(presets[p].end) - Date.parse(presets[p].start)
    && Math.abs(Date.parse(filters.end ?? '') - Date.parse(presets[p].end)) < 60 * 60_000)
  const timeValue = !filters.start && !filters.end ? 'all' : activePreset ?? 'custom'
  const [customOpen, setCustomOpen] = useState(timeValue === 'custom')
  const [from, setFrom] = useState(inputFromUtc(filters.start ?? undefined))
  const [to, setTo] = useState(inputFromUtc(filters.end ?? undefined))

  // Apply a change on top of the active filters (undefined removes a filter).
  function apply(patch: Partial<EventFilters>) {
    const next = { ...filters, ...patch }
    for (const key of Object.keys(next) as (keyof EventFilters)[]) {
      if (next[key] === undefined || next[key] === '' || next[key] === false) delete next[key]
    }
    onApply(next)
  }

  function submitSearch(event: FormEvent) {
    event.preventDefault()
    apply({ q: search.trim() || undefined })
  }

  function selectTime(value: string) {
    if (value === 'custom') return setCustomOpen(true)
    setCustomOpen(false)
    if (value === 'all') return apply({ start: undefined, end: undefined })
    const preset = timePresets()[value as TimePreset] // recomputed at click time: "now" moves
    if (preset) apply({ start: preset.start, end: preset.end })
  }

  const chips = ([['username', 'User'], ['host', 'Host'], ['category', 'Category']] as const)
    .filter(([key]) => filters[key])
  // Links from the dashboard ("Flagged" counts) open Logs with ?flagged=1: shown as a chip.
  const any = Object.keys(filters).length > 0

  // One row of filters; custom range and value chips only appear when used.
  return (
    <div className="flex flex-col gap-3 rounded-xl border bg-card p-3">
      <div className="flex flex-wrap items-center gap-2">
        <form onSubmit={submitSearch} role="search" className="relative min-w-56 flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input aria-label="Search events" value={search} onChange={(e) => setSearch(e.target.value)}
                 placeholder="Search user, IP, domain, category, device…" className="h-9 pl-8" />
        </form>
        <select aria-label="Time range" className={SELECT} value={customOpen ? 'custom' : timeValue}
                onChange={(e) => selectTime(e.target.value)}>
          <option value="all">All logs</option>
          {(Object.keys(presets) as TimePreset[]).map((p) => <option key={p} value={p}>{presets[p].label}</option>)}
          <option value="custom">Custom range…</option>
        </select>
        {/* Sources: checked sources are OR-ed (a matched rule, or inside a finding window). */}
        <MultiSelect label="Sources" allLabel="All sources" selected={filters.source ?? []}
                     options={SOURCE_VALUES.map((v) => ({ value: v, label: SOURCE_LABELS[v] }))}
                     onChange={(v) => apply({ source: v.length ? (v as EventFilters['source']) : undefined })} />
        <div role="group" aria-label="Action" className="inline-flex rounded-lg border p-0.5">
          {([['', 'All'], ['Allowed', 'Allowed'], ['Blocked', 'Blocked']] as const).map(([value, label]) => (
            <button key={label} type="button" aria-pressed={(filters.action ?? '') === value}
                    onClick={() => apply({ action: (value || undefined) as EventFilters['action'] })}
                    className={cn('rounded-md px-3 py-1 text-sm', (filters.action ?? '') === value
                      ? 'bg-accent font-medium text-accent-foreground' : 'text-muted-foreground hover:text-foreground')}>
              {label}
            </button>
          ))}
        </div>
        {/* Segmented like Action: each side says what the table shows; "All" is no filter. */}
        <div role="group" aria-label="Anomalies" title="Anomalies: lines that matched a rule or sit inside a finding's time window"
             className="inline-flex rounded-lg border p-0.5">
          {([[false, 'All events'], [true, 'Anomalies only']] as const).map(([value, label]) => (
            <button key={label} type="button" aria-pressed={!!filters.anomalous === value}
                    onClick={() => apply({ anomalous: value || undefined })}
                    className={cn('rounded-md px-3 py-1 text-sm', !!filters.anomalous === value
                      ? 'bg-accent font-medium text-accent-foreground' : 'text-muted-foreground hover:text-foreground')}>
              {label}
            </button>
          ))}
        </div>
        {any && (
          <Button variant="ghost" size="sm" className="ml-auto h-9" onClick={() => onApply({})}>Clear all</Button>
        )}
      </div>

      {customOpen && (
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => {
          e.preventDefault()
          apply({ start: utcFromInput(from) || undefined, end: utcFromInput(to) || undefined })
        }}>
          <label className="flex flex-col gap-1 text-sm"><span className="label-caps">From (UTC)</span>
            <Input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} className="h-9 w-56" />
          </label>
          <label className="flex flex-col gap-1 text-sm"><span className="label-caps">To (UTC)</span>
            <Input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} className="h-9 w-56" />
          </label>
          <Button type="submit" size="sm" className="h-9">Apply range</Button>
        </form>
      )}

      {(filters.flagged || chips.length > 0) && (
        <div className="flex flex-wrap items-center gap-2">
        {filters.flagged && (
          <span className="inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-sm">
            Any rule match
            <button type="button" aria-label="Remove rule-match filter" className="text-muted-foreground hover:text-foreground"
                    onClick={() => apply({ flagged: undefined })}><X className="size-3.5" /></button>
          </span>
        )}
        {chips.map(([key, label]) => (
          <span key={key} className="inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-sm">
            {label}: <span className="tech">{filters[key]}</span>
            <button type="button" aria-label={`Remove ${label.toLowerCase()} filter`} className="text-muted-foreground hover:text-foreground"
                    onClick={() => apply({ [key]: undefined })}><X className="size-3.5" /></button>
          </span>
        ))}
        </div>
      )}

      {/* Always say what is being searched. */}
      <p className="meta" aria-live="polite">
        Searching{' '}
        {filters.start || filters.end ? (
          <b className="font-medium text-foreground">
            {filters.start ? formatUtc(filters.start) : 'the start'} – {filters.end ? formatUtc(filters.end) : 'the end'}
          </b>
        ) : <b className="font-medium text-foreground">all logs</b>}
        {' '}in this dataset
        {bounds?.first && bounds.last && ` (${formatUtc(bounds.first)} – ${formatUtc(bounds.last)})`}
        {activePreset && '. "Last" counts back from now.'}
      </p>
    </div>
  )
}
