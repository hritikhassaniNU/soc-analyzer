import { CircleCheck, CircleDashed, CircleDot } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { type Investigation, type InvestigationFilters, useInvestigations } from '@/api/investigations'
import MultiSelect from '@/components/MultiSelect'
import Pagination from '@/components/Pagination'
import RiskMeter from '@/components/RiskMeter'
import SortHeader from '@/components/SortHeader'
import CasesPerDay from '@/components/investigations/CasesPerDay'
import { SeverityPill } from '@/components/investigations/Labels'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateTime, formatUtc } from '@/lib/format'
import { formatWindow, kindLabel, PRIORITY_META, PRIORITY_ORDER, severityOptions } from '@/lib/incidents'
import { STATUS_ICON_CLASS, STATUS_LABELS } from '@/lib/investigations'
import { paginate } from '@/lib/pagination'
import { paramsForSort, sortFrom, sortRows } from '@/lib/sorting'
import { userPath } from '@/lib/users'
import { cn } from '@/lib/utils'

type Priority = Investigation['priority']
const CASE_SORTS = ['risk', 'alerts', 'status', 'occurred'] as const
type CaseSort = (typeof CASE_SORTS)[number]
// Highest first = riskiest / most alerts / open before resolved / newest.
const STATUS_RANK = { open: 3, investigating: 2, resolved: 1 } as const
const CASE_SORT_VALUE: Record<CaseSort, (c: Investigation) => number> = {
  risk: (c) => c.risk, alerts: (c) => c.alerts, status: (c) => STATUS_RANK[c.status], occurred: (c) => Date.parse(c.start_ts),
}

// Status: icon shape + word (never color alone; severity colors stay reserved for severity).
const STATUS_ICON = { open: CircleDot, investigating: CircleDashed, resolved: CircleCheck } as const

/** Server filters from the URL (?q=&status=&detector=); severity is filtered here so the chips can
 *  show counts for every severity (?severity=critical,high). */
function serverFilters(params: URLSearchParams): InvestigationFilters {
  const f: InvestigationFilters = {}
  const q = params.get('q')?.trim()
  if (q) f.q = q
  const detector = params.get('detector') // from Detection Rules "View cases"
  if (detector) f.detector = detector
  return f
}

/** The case queue: severity chips with counts, compact one-line cases, unresolved first,
 *  25 per page. Everything lives in the URL. */
export default function InvestigationsPage() {
  const [params, setParams] = useSearchParams()
  const filters = serverFilters(params)
  const severities = (params.get('severity') ?? '').split(',').filter((s): s is Priority => s in PRIORITY_META)
  // Status checkboxes; the older ?status=unresolved means open + investigating.
  const rawStatus = params.get('status') === 'unresolved' ? 'open,investigating' : params.get('status') ?? ''
  const statuses = rawStatus.split(',').filter((s): s is Investigation['status'] => s in STATUS_LABELS)
  const [search, setSearch] = useState(filters.q ?? '')
  const list = useInvestigations(filters)
  const navigate = useNavigate()

  function set(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (key !== 'page') next.delete('page') // a new filter starts at page 1
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next)
  }

  function submitSearch(event: FormEvent) {
    event.preventDefault() // search on Enter, not on every keystroke
    set('q', search.trim())
  }

  const all = list.data ?? []
  const counts = Object.fromEntries(PRIORITY_ORDER.map((p) => [p, all.filter((c) => c.priority === p).length]))
  const day = /^\d{4}-\d{2}-\d{2}$/.test(params.get('day') ?? '') ? params.get('day') : null // from the chart
  const beforeDay = all.filter((c) => (severities.length === 0 || severities.includes(c.priority))
    && (statuses.length === 0 || statuses.includes(c.status)))
  const shown = day ? beforeDay.filter((c) => c.start_ts.startsWith(day)) : beforeDay
  const statusCounts = Object.fromEntries(Object.keys(STATUS_LABELS).map((st) => [st, all.filter((c) => c.status === st).length]))
  // Sorting: default = the server's order (unresolved first, worst first).
  const sorting = sortFrom(params, CASE_SORTS)
  const sorted = sorting.sort ? sortRows(shown, CASE_SORT_VALUE[sorting.sort], sorting.dir, (a, b) => a.id - b.id) : shown
  const paged = paginate(sorted, Number(params.get('page') ?? '1'))
  const sortHead = (key: CaseSort, label: string, align?: 'right') => (
    <SortHeader label={label} align={align} className="label-caps" active={sorting.sort === key} dir={sorting.dir}
                onSort={() => setParams(paramsForSort(params, sorting, key))} />
  )
  const filtered = Object.keys(filters).length > 0 || severities.length > 0 || statuses.length > 0 || !!day

  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="page-title">Investigations</h1>
        <p className="page-subtitle">Correlated incidents requiring analyst investigation; unresolved first.</p>
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <form onSubmit={submitSearch} role="search">
            <Input aria-label="Search investigations" placeholder="Search number, user, domain…" value={search}
                   onChange={(e) => setSearch(e.target.value)} className="h-9 w-64" />
          </form>
          <MultiSelect label="Severity" allLabel="All severity" selected={severities}
                       options={severityOptions(counts)} onChange={(v) => set('severity', v.join(','))} />
          <MultiSelect label="Status" allLabel="All status" selected={statuses} onChange={(v) => set('status', v.join(','))}
                       options={Object.entries(STATUS_LABELS).map(([value, label]) => ({ value, label, count: statusCounts[value] }))} />
          {filters.detector && (
            <span className="inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-sm">
              Detector: {kindLabel(filters.detector)}
              <button type="button" aria-label="Remove detector filter" className="text-muted-foreground hover:text-foreground"
                      onClick={() => set('detector', '')}>×</button>
            </span>
          )}
          {filtered && (
            <button type="button" className="h-9 px-2 text-sm text-muted-foreground hover:text-foreground"
                    onClick={() => { setSearch(''); setParams(new URLSearchParams()) }}>
              Clear filters
            </button>
          )}
          <span className="meta ml-auto">{shown.length} of {all.length} cases</span>
        </div>
      </div>

      {/* The chart follows every filter except the day it selects. */}
      <CasesPerDay cases={beforeDay} selected={day} onSelect={(d) => set('day', d ?? '')} severities={severities}
                   onToggleSeverity={(p) => set('severity', (severities.includes(p) ? severities.filter((s) => s !== p) : [...severities, p]).join(','))} />
      {day && (
        <span className="inline-flex h-9 w-fit items-center gap-2 rounded-lg border px-3 text-sm">
          Occurred on {new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}
          <button type="button" aria-label="Remove day filter" className="text-muted-foreground hover:text-foreground" onClick={() => set('day', '')}>×</button>
        </span>
      )}
      {list.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
      {list.isError && <p className="text-sm text-muted-foreground">Couldn't load investigations. Try again.</p>}
      {list.data && shown.length === 0 && (
        <p className="text-sm text-muted-foreground">
          {filtered ? 'No investigations match these filters.' : 'No investigations yet. Upload and analyze a log file to start.'}
        </p>
      )}
      {shown.length > 0 && (
        <div className={cn('overflow-x-auto rounded-xl border bg-card transition-opacity', list.isPlaceholderData && 'opacity-60')}>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Severity</TableHead>
                <TableHead className="label-caps">Incident</TableHead>
                <TableHead className="label-caps">Entities</TableHead>
                {sortHead('risk', 'Risk')}
                {sortHead('alerts', 'Evidence')}
                {sortHead('status', 'Status')}
                {sortHead('occurred', 'Occurred (UTC)')}
              </TableRow>
            </TableHeader>
            <TableBody>
              {paged.items.map((c) => <CaseRow key={c.id} c={c} onOpen={() => navigate(`/investigations/${c.id}`)} />)}
            </TableBody>
          </Table>
          {paged.pages > 1 && (
            <div className="border-t px-4 py-3">
              <Pagination page={paged.page} pages={paged.pages} from={paged.from} to={paged.to} total={paged.total}
                          noun="cases" onPage={(n) => set('page', n === 1 ? '' : String(n))} />
            </div>
          )}
        </div>
      )}
    </main>
  )
}

function CaseRow({ c, onOpen }: { c: Investigation; onOpen: () => void }) {
  const user = c.entities.find((e) => e.type === 'user')?.name
  const others = c.entities.filter((e) => e.type !== 'user')
  const othersText = others.map((e) => `${e.type === 'ip' ? 'IP' : e.type[0].toUpperCase() + e.type.slice(1)} ${e.name}`).join(', ')
  const StatusIcon = STATUS_ICON[c.status]
  return (
    // The whole row opens the case; the number is also a real link (keyboard, new tab).
    <TableRow className={cn('cursor-pointer', c.status === 'resolved' && 'opacity-70')} onClick={onOpen}>
      <TableCell><SeverityPill priority={c.priority} /></TableCell>
      <TableCell className="max-w-96 whitespace-normal">
        <Link to={`/investigations/${c.id}`} onClick={(e) => e.stopPropagation()} className="hover:underline">
          <span className="tech font-semibold">{c.number}</span> <span className="font-medium">{c.name}</span>
        </Link>
        <p className="meta">{user ? `${user} · ` : ''}{formatWindow(c.start_ts, c.end_ts)}</p>
      </TableCell>
      <TableCell className="whitespace-nowrap">
        {user && (
          <Link to={userPath(user)} onClick={(e) => e.stopPropagation()} className="font-medium hover:underline">{user}</Link>
        )}
        {others.length > 0 && (
          // The rest on hover (title) and for screen readers (sr-only): log text, plain only.
          <span className="ml-2 rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground" title={othersText}>
            +{others.length}<span className="sr-only">: {othersText}</span>
          </span>
        )}
      </TableCell>
      <TableCell>
        <RiskMeter risk={c.risk} priority={c.priority} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-muted-foreground" title="Signals = independent kinds of evidence that drive the risk">
        {c.alerts} alert{c.alerts === 1 ? '' : 's'} · {c.signals} signal{c.signals === 1 ? '' : 's'}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <span className="inline-flex items-center gap-1.5">
          <StatusIcon className={cn('size-3.5', STATUS_ICON_CLASS[c.status])} aria-hidden />
          {STATUS_LABELS[c.status]}
        </span>
        <span className="meta"> · {c.owner ?? 'unassigned'}</span>
      </TableCell>
      <TableCell className="whitespace-nowrap text-muted-foreground">
        <time dateTime={c.start_ts} title={`Last updated ${formatDateTime(c.updated_at)}`}>{formatUtc(c.start_ts)}</time>
      </TableCell>
    </TableRow>
  )
}
