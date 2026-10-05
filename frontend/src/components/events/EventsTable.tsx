import { ChevronDown, ChevronRight, TriangleAlert } from 'lucide-react'
import { Fragment, useState } from 'react'
import { Link } from 'react-router'
import { type EventFilters, type EventRow, EVENTS_PAGE_SIZE, useDatasetBounds, useEventCount, useEvents } from '@/api/events'
import Pagination from '@/components/Pagination'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { cn } from '@/lib/utils'
import { formatBytes, formatUtc } from '@/lib/format'
import { kindLabel, PRIORITY_META, SEVERITY_COLORS } from '@/lib/incidents'
import { HIGH_SCORE, ruleLabel } from '@/lib/rules'
import { userPath } from '@/lib/users'

const timeFormat = new Intl.DateTimeFormat(undefined, {
  weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
  hour12: false, timeZone: 'UTC',
})

/**
 * Server-filtered log lines, 75 per page with page numbers (D86). The page lives in the URL;
 * Next/Previous continue by keyset, page numbers jump with an offset (see useEvents).
 */
export default function EventsTable({ uploadId, filters, page, onPage }: {
  uploadId: number; filters: EventFilters; page: number; onPage: (page: number) => void
}) {
  const count = useEventCount(uploadId, filters)
  const bounds = useDatasetBounds(uploadId).data
  const [now] = useState(() => Date.now()) // read once (render must stay pure)
  const total = count.data?.total ?? null
  const pages = total === null ? Math.max(page, 1) : Math.max(1, Math.ceil(total / EVENTS_PAGE_SIZE))
  const current = Math.min(Math.max(1, page), pages) // a hand-edited ?page=99999 shows the last page
  const events = useEvents(uploadId, filters, current)

  if (events.isPending) return <p className="text-sm text-muted-foreground">Loading events…</p>
  if (events.isError) {
    return (
      <div className="flex items-center gap-3 text-sm text-muted-foreground">
        Can't load events.
        <Button variant="outline" size="sm" onClick={() => events.refetch()}>Retry</Button>
      </div>
    )
  }

  const { items } = events.data
  const first = (current - 1) * EVENTS_PAGE_SIZE + 1
  if (items.length === 0 && current === 1) {
    return (
      <p className="text-sm text-muted-foreground">
        No events match these filters.
        {(filters.start || filters.end) && bounds?.first && bounds.last && (
          Date.parse(bounds.first) > now ? (
            // Every event is dated after now (wrong log timezone, a device clock, or test data):
            // a "Last N" range can't include it. Say so plainly (D114).
            <> Every event in this dataset is dated <b className="font-medium text-foreground">in the future</b> (from{' '}
              {formatUtc(bounds.first)}), so a "Last" range can't include it. Choose All logs or a custom range; future
              timestamps usually mean a wrong log timezone or device clock.</>
          ) : (
            <> This dataset covers {formatUtc(bounds.first)} – {formatUtc(bounds.last)}; try a wider time range.</>
          )
        )}
      </p>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {/* Dimmed while the next page loads (previous rows stay: no flicker, no layout jump). */}
      <div className={cn('overflow-x-auto transition-opacity', events.isPlaceholderData && 'opacity-60')}>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8"><span className="sr-only">Details</span></TableHead>
              <TableHead>Time (UTC)</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead title="Zscaler's category of the website (from the log's url_category field)">URL category</TableHead>
              <TableHead className="text-right">Risk</TableHead>
              <TableHead className="text-right">Sent / received</TableHead>
              <TableHead>Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((event) => (
              <EventTableRow key={event.line_no} event={event} />
            ))}
          </TableBody>
        </Table>
      </div>

      <Pagination page={current} pages={pages} from={first} to={first + items.length - 1} total={total}
                  noun="events" onPage={onPage} busy={events.isPlaceholderData} />
    </div>
  )
}

const COLUMN_COUNT = 9

function EventTableRow({ event }: { event: EventRow }) {
  const [open, setOpen] = useState(false)
  const flagged = event.rule_hits.length > 0
  const high = event.rule_max_score >= HIGH_SCORE
  // The line's rule score in the incident bands (D105): its dot and its row accent use that color.
  const scoreLevel = event.rule_max_score >= 0.95 ? 'critical' : high ? 'high' : event.rule_max_score >= 0.45 ? 'medium' : 'low'
  const inWindow = event.windows.length > 0
  return (
    <Fragment>
      <TableRow
        // Flagged rows: a left accent bar + an icon + rule names (never color alone).
        className={cn(
          'align-top border-l-2 border-l-transparent',
          flagged && 'border-l-muted-foreground/40',
          inWindow && 'bg-muted dark:bg-muted/70', // inside a finding's window (neutral: priority colors are reserved)
          scoreLevel === 'critical' && 'border-l-priority-critical bg-priority-critical/5',
          scoreLevel === 'high' && 'border-l-priority-high bg-priority-high/5',
        )}
      >
        <TableCell>
          {/* A real button: keyboard-accessible, announces expanded/collapsed. */}
          <Button
            variant="ghost"
            size="icon-sm"
            aria-expanded={open}
            aria-label={open ? 'Hide details' : 'Show details'}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? <ChevronDown /> : <ChevronRight />}
          </Button>
        </TableCell>
        <TableCell className="tabular-nums whitespace-nowrap">{timeFormat.format(new Date(event.ts))}</TableCell>
        <TableCell><Link to={userPath(event.username)} className="hover:underline">{event.username}</Link></TableCell>
        <TableCell>
          {/* Outcome (D110): the same soft tinted badge for both, like the upload status badges. */}
          {event.action === 'Blocked' ? (
            <Badge variant="destructive">Blocked</Badge>
          ) : (
            <Badge className="bg-status-success/15 text-status-success">Allowed</Badge>
          )}
        </TableCell>
        <TableCell className="max-w-72">
          {/* Log text is attacker-controlled: rendered as plain text, full URL on hover. */}
          <div className="truncate" title={event.url}>
            <span className="text-muted-foreground">{event.method ?? ''} </span>
            <span className="tech">{event.host ?? event.url}</span>
          </div>
        </TableCell>
        <TableCell className="whitespace-nowrap">{event.category ?? '—'}</TableCell>
        {/* Zscaler's page risk: high values (>= 75, the rule threshold) in the High severity color. */}
        <TableCell className={cn('text-right tabular-nums', event.risk_score >= 75 && 'font-semibold text-priority-high')}>
          {event.risk_score}
        </TableCell>
        <TableCell className="text-right tabular-nums whitespace-nowrap">
          {formatBytes(event.bytes_out)} / {formatBytes(event.bytes_in)}
        </TableCell>
        <TableCell>
          {inWindow && (
            // Window-level marks, worded so they're never color alone.
            <div className="mb-1 flex flex-wrap gap-1">
              {event.windows.map((kind) => (
                <Badge key={kind} variant="outline" title="Inside this finding's time window">
                  {kindLabel(kind)}
                </Badge>
              ))}
            </div>
          )}
          {flagged && (
            <div className="flex flex-wrap items-center gap-1">
              {high && <TriangleAlert className={cn('size-4', PRIORITY_META[scoreLevel].iconClass)} aria-label="High score" />}
              {event.rule_hits.map((rule) => (
                <Badge key={rule} variant="secondary">{ruleLabel(rule)}</Badge>
              ))}
              {/* The row's highest rule score: lets an analyst triage at a glance (0.2 update vs 0.8 malware). */}
              <span className="inline-flex items-center gap-1 text-xs text-muted-foreground tabular-nums"
                    title={`Highest rule score (0-100): ${PRIORITY_META[scoreLevel].label.toLowerCase()} (ranking signal, not a probability)`}>
                <span className="size-1.5 rounded-full" style={{ background: SEVERITY_COLORS[scoreLevel] }} aria-hidden />
                {Math.round(event.rule_max_score * 100)}
              </span>
            </div>
          )}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={COLUMN_COUNT} className="whitespace-normal">
            <EventDetails event={event} />
          </TableCell>
        </TableRow>
      )}
    </Fragment>
  )
}

/** Every field of the log line. All values are attacker-controlled text: rendered as plain text. */
function EventDetails({ event }: { event: EventRow }) {
  const fields: [string, string][] = [
    ['Line', event.line_no.toLocaleString()],
    ['Full URL', event.url],
    ['Client IP', event.client_ip],
    ['Device', event.device ? [event.device, event.device_os].filter(Boolean).join(' · ') : '—'],
    ['User agent', event.user_agent ?? '—'],
    ['Status code', event.status_code?.toString() ?? '—'],
    ['Zscaler threat', event.threat ?? 'None'],
    ['File type', event.file_type ?? '—'],
    ['Bytes sent / received', `${event.bytes_out.toLocaleString()} / ${event.bytes_in.toLocaleString()}`],
    ['Rules', event.rule_hits.length ? event.rule_hits.map(ruleLabel).join(', ') : 'None'],
    ['Inside', event.windows.length ? event.windows.map(kindLabel).join(', ') : 'No finding window'],
  ]
  return (
    <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 py-1 text-xs">
      {fields.map(([label, value]) => (
        <Fragment key={label}>
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="break-all font-mono">{value}</dd>
        </Fragment>
      ))}
    </dl>
  )
}
