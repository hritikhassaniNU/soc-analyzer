import { ArrowRight, ChevronDown, ChevronRight, Info } from 'lucide-react'
import { useId, useState } from 'react'
import { Link } from 'react-router'
import { type Incident, type Priority, useIncidents } from '@/api/incidents'
import { Button, buttonVariants } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SourceLabel } from '@/components/SourceLabel'
import { drillDownParams } from '@/lib/eventFilters'
import { cn } from '@/lib/utils'
import { formatTime, formatWindow, kindLabel, PRIORITY_META, PRIORITY_ORDER, SCORE_HELP, SOURCE_LABELS } from '@/lib/incidents'

/**
 * "Who do I look at first?": incidents worst first, medium and above by default.
 * Every row expands to the evidence (each finding's reason), all rendered as plain text.
 */
export default function IncidentsPanel({ uploadId, aiWritten = false }: { uploadId: number; aiWritten?: boolean }) {
  const [showLow, setShowLow] = useState(false)
  const incidents = useIncidents(uploadId, showLow, true)

  return (
    <Card>
      <CardHeader className="flex flex-wrap items-center justify-between gap-2">
        <CardTitle>Incidents</CardTitle>
        {incidents.data && <Counts counts={incidents.data.counts} />}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <ScoreHelp />
        {incidents.isPending && <p className="text-sm text-muted-foreground">Loading incidents…</p>}
        {incidents.isError && (
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            Can't load incidents.
            <Button variant="outline" size="sm" onClick={() => incidents.refetch()}>Retry</Button>
          </div>
        )}
        {incidents.data && (
          <>
            {incidents.data.incidents.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {showLow ? 'No incidents in this upload.' : 'No medium, high or critical incidents.'}
              </p>
            ) : (
              <ul className={cn('divide-y rounded-md border', incidents.isPlaceholderData && 'opacity-60')}>
                {incidents.data.incidents.map((incident) => (
                  <IncidentRow key={incident.id} uploadId={uploadId} incident={incident} aiWritten={aiWritten} />
                ))}
              </ul>
            )}
            {incidents.data.counts.low > 0 && (
              <div>
                <Button variant="outline" size="sm" onClick={() => setShowLow((v) => !v)}>
                  {showLow ? 'Hide low priority' : `Show ${incidents.data.counts.low} low priority`}
                </Button>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function Counts({ counts }: { counts: Record<string, number> }) {
  return (
    <p className="flex flex-wrap gap-3 text-sm text-muted-foreground">
      {PRIORITY_ORDER.map((p) => (
        <span key={p} className="tabular-nums">
          <span className="font-medium text-foreground">{counts[p] ?? 0}</span> {PRIORITY_META[p].label.toLowerCase()}
        </span>
      ))}
    </p>
  )
}

/** A real button that reveals the explanation: works with keyboard, touch and screen readers. */
function ScoreHelp() {
  const [open, setOpen] = useState(false)
  const id = useId()
  return (
    <div className="text-sm">
      <button
        type="button"
        className="inline-flex items-center gap-1 text-muted-foreground underline-offset-2 hover:underline"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((v) => !v)}
      >
        Confidence score (heuristic) <Info className="size-3.5" aria-hidden />
      </button>
      {open && (
        <p id={id} className="mt-1 max-w-prose text-muted-foreground">
          {SCORE_HELP}
        </p>
      )}
    </div>
  )
}

export function PriorityLabel({ priority }: { priority: Priority }) {
  const { label, icon: Icon, iconClass } = PRIORITY_META[priority]
  return (
    <span className="inline-flex items-center gap-1.5 font-medium">
      <Icon className={cn('size-4 shrink-0', iconClass)} aria-hidden />
      {label}
    </span>
  )
}

function IncidentRow({ uploadId, incident, aiWritten }: { uploadId: number; incident: Incident; aiWritten: boolean }) {
  const [open, setOpen] = useState(false)
  const findings = incident.anomalies.length
  return (
    <li className="px-3 py-2">
      <div className="flex items-start gap-2">
        <Button
          variant="ghost"
          size="icon-sm"
          aria-expanded={open}
          aria-label={open ? 'Hide evidence' : 'Show evidence'}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? <ChevronDown /> : <ChevronRight />}
        </Button>
        <div className="grid flex-1 gap-x-4 gap-y-0.5 sm:grid-cols-[7rem_3rem_7rem_1fr]">
          <PriorityLabel priority={incident.priority} />
          <span className="tabular-nums text-muted-foreground" title="Confidence score (heuristic), not a probability">
            {incident.priority_score.toFixed(2)}
          </span>
          <span className="truncate font-medium" title={incident.username}>{incident.username}</span>
          <span className="text-muted-foreground tabular-nums">{formatWindow(incident.start_ts, incident.end_ts)} UTC</span>
          <span className="sm:col-start-3 sm:col-span-2">
            {incident.title}
            <span className="text-muted-foreground"> · {findings} finding{findings === 1 ? '' : 's'}</span>
          </span>
        </div>
        {/* Drill-down: the Events tab filtered to this user and window (a real link: new tab, Back). */}
        <Link
          to={{ pathname: '/logs', search: drillDownParams(uploadId, incident.username, incident.start_ts, incident.end_ts).toString() }}
          className={cn(buttonVariants({ variant: 'outline', size: 'sm' }), 'shrink-0')}
        >
          View events <ArrowRight aria-hidden />
        </Link>
      </div>
      {open && (
        <>
          {incident.narrative && <Written incident={incident} aiWritten={aiWritten} />}
          <Evidence incident={incident} />
        </>
      )}
    </li>
  )
}

/** The written narrative and next steps (AI or template), labeled, as plain text. */
function Written({ incident, aiWritten }: { incident: Incident; aiWritten: boolean }) {
  return (
    <div className="mt-2 ml-10 flex max-w-prose flex-col gap-2 rounded-md bg-muted/40 p-3 text-sm">
      <SourceLabel ai={aiWritten} />
      <p>{incident.narrative}</p>
      {incident.next_steps.length > 0 && (
        <div>
          <p className="font-medium">Suggested next steps</p>
          <ul className="ml-5 list-disc text-muted-foreground">
            {incident.next_steps.map((step) => <li key={step}>{step}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}

/** The findings behind an incident, in time order. Reasons can contain log text: plain text only. */
function Evidence({ incident }: { incident: Incident }) {
  return (
    <ol className="mt-2 ml-10 flex flex-col gap-2 border-l pl-4 text-sm">
      {incident.anomalies.map((finding) => (
        <li key={finding.id}>
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="tabular-nums text-muted-foreground">{formatTime(finding.window_start)}</span>
            <span className="font-medium">{kindLabel(finding.kind)}</span>
            <span className="tabular-nums text-muted-foreground">{finding.score.toFixed(2)}</span>
            <span className="text-xs text-muted-foreground">{SOURCE_LABELS[finding.source] ?? finding.source}</span>
          </div>
          <p className="break-words text-muted-foreground">{finding.reason}</p>
        </li>
      ))}
    </ol>
  )
}
