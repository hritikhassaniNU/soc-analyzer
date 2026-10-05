import { ArrowLeft } from 'lucide-react'
import { Link, useParams, useSearchParams } from 'react-router'
import { type InvestigationDetail, useInvestigation } from '@/api/investigations'
import { SourceLabel } from '@/components/SourceLabel'
import VolumeChart from '@/components/charts/VolumeChart'
import CaseNotes from '@/components/investigations/CaseNotes'
import CaseActions from '@/components/investigations/CaseActions'
import CaseDetails from '@/components/investigations/CaseDetails'
import { SeverityPill, StatusPill } from '@/components/investigations/Labels'
import { AiAssessment, CaseSearches } from '@/components/investigations/CaseTriage'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { bucketLabel, capitalize } from '@/lib/format'
import { formatWindow, SEVERITY_COLORS } from '@/lib/incidents'
import { userPath } from '@/lib/users'
import { cn } from '@/lib/utils'
import NotFoundPage from '@/pages/NotFoundPage'

const TABS = [
  ['overview', 'Overview'],
  ['timeline', 'Timeline'],
  ['entities', 'Entities'],
  ['evidence', 'Evidence'],
  ['ai', 'AI Analysis'],
  ['notes', 'Notes'],
] as const
type Tab = (typeof TABS)[number][0]

const ENTITY_TYPES = { user: 'User', device: 'Device', ip: 'Source IP', domain: 'Domain' } as const
const SOURCE_NAMES = { rule: 'rule', stat: 'statistics', ml: 'machine learning', ai: 'AI (Claude)' } as const

export default function InvestigationDetailPage() {
  const { caseId } = useParams()
  const id = Number(caseId)
  if (!Number.isInteger(id) || id <= 0) return <NotFoundPage />
  return <Detail id={id} />
}

function Detail({ id }: { id: number }) {
  const inv = useInvestigation(id)
  const [params, setParams] = useSearchParams()
  const tab: Tab = TABS.some(([value]) => value === params.get('tab')) ? (params.get('tab') as Tab) : 'overview'

  function selectTab(value: string) {
    const next = new URLSearchParams(params)
    if (value === 'overview') next.delete('tab')
    else next.set('tab', value)
    setParams(next) // in the URL: Back works, links can open a tab
  }

  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <Link to="/investigations" className="flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> Back to investigations
      </Link>
      {inv.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
      {inv.isError && <p className="text-sm text-muted-foreground">Investigation not found. Its upload may have been deleted.</p>}
      {inv.data && (
        <>
          <Header d={inv.data} />
          {/* Tab bar above both columns, so the tab content and the Case details panel start at the
              same height (D115). */}
          <Tabs value={tab} onValueChange={selectTab} className="min-w-0">
            <TabsList variant="line">
              {TABS.map(([value, label]) => (
                <TabsTrigger key={value} value={value}>
                  {label}
                  {value === 'notes' && inv.data.notes.length > 0 && (
                    <span className="text-muted-foreground tabular-nums">({inv.data.notes.length})</span>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>
            <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
              <div className="min-w-0">
                <TabsContent value="overview"><Overview d={inv.data} /></TabsContent>
                <TabsContent value="timeline"><Timeline d={inv.data} /></TabsContent>
                <TabsContent value="entities"><Entities d={inv.data} /></TabsContent>
                <TabsContent value="evidence"><Evidence d={inv.data} /></TabsContent>
                <TabsContent value="ai"><AiAnalysis d={inv.data} /></TabsContent>
                <TabsContent value="notes"><CaseNotes d={inv.data} /></TabsContent>
              </div>
              <CaseDetails d={inv.data} />
            </div>
          </Tabs>
        </>
      )}
    </main>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-4 rounded-xl border bg-card p-6">
      <h2 className="section-title">{title}</h2>
      {children}
    </section>
  )
}

/** Compact case header (D91): number + severity + status pills, title, window, and the actions. */
function Header({ d }: { d: InvestigationDetail }) {
  return (
    <section className="flex flex-wrap items-start justify-between gap-4 rounded-xl border bg-card p-5">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="tech text-muted-foreground">{d.number}</span>
          <SeverityPill priority={d.priority} />
          <StatusPill status={d.status} />
        </div>
        <h1 className="page-title mt-1.5">{d.name}</h1>
        <p className="page-subtitle">{formatWindow(d.start_ts, d.end_ts)} UTC · {d.title}</p>
      </div>
      <CaseActions d={d} />
    </section>
  )
}

function Overview({ d }: { d: InvestigationDetail }) {
  return (
    <div className="flex flex-col gap-6">
    {/* Triage first (D135): the AI's suggestion, then one-click searches. */}
    <AiAssessment d={d} />
    <CaseSearches d={d} className="rounded-xl border bg-card px-4 py-3" />
    <div className="grid items-start gap-6 xl:grid-cols-[1.4fr_1fr]">
      <Panel title="Why flagged">
        {d.why_flagged ? (
          <>
            {/* Plain text: it can quote log-derived names. */}
            <p className="leading-relaxed">{d.why_flagged}</p>
            {d.narrative_source && <SourceLabel ai={d.narrative_source === 'ai'} />}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">No written summary for this incident.</p>
        )}
        <h3 className="mt-2 subsection-title">Risk breakdown</h3>
        <ul className="flex flex-col gap-3">
          {d.risk_breakdown.map((p) => (
            <li key={p.category} className="flex flex-col gap-1 text-sm">
              <div className="flex justify-between gap-3">
                <span>
                  {capitalize(p.label)}
                  {!p.counted && <span className="text-muted-foreground"> · not counted</span>}
                </span>
                <span className="font-semibold tabular-nums">{p.weight}</span>
              </div>
              <div className="h-2 rounded-full bg-muted">
                <div className="h-2 rounded-full" style={{
                  width: `${p.weight}%`,
                  background: p.counted ? 'var(--series-1)' : 'var(--muted-foreground)',
                }} />
              </div>
            </li>
          ))}
        </ul>
        <RiskSentence d={d} />
      </Panel>
      <Panel title="Detection signals">
        <p className="-mt-2 text-xs text-muted-foreground">
          {d.signals} of {d.detection_signals.length} evidence categories count toward the risk.
        </p>
        <ul className="flex flex-col gap-3">
          {d.detection_signals.map((s) => (
            <li key={s.category} className={cn('rounded-lg border px-4 py-3', !s.counted && 'opacity-70')}>
              <p className="font-semibold">
                {capitalize(s.label)}
                {!s.counted && <span className="font-normal text-muted-foreground"> · evidence only</span>}
              </p>
              <p className="text-sm text-muted-foreground">{s.description}</p>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
    </div>
  )
}

/** "Risk 100: driven by command & control (90), +10 each for executable download and unusual hours.
 *  A ranking for triage, not a probability." Built from this case's real breakdown (D95). */
function RiskSentence({ d }: { d: InvestigationDetail }) {
  const [top, ...rest] = d.risk_breakdown
  if (!top) return null
  const extras = rest.filter((p) => p.counted).map((p) => p.label)
  const list = extras.length > 1 ? `${extras.slice(0, -1).join(', ')} and ${extras.at(-1)}` : extras[0]
  return (
    <p className="text-xs text-muted-foreground">
      Risk {d.risk}: driven by {top.label} ({top.weight}){list ? `, +10 each for ${list}` : ''}
      {d.risk === 100 && top.weight + 10 * extras.length > 100 ? ' (capped at 100)' : ''}. A ranking for triage, not a probability.
    </p>
  )
}

function Timeline({ d }: { d: InvestigationDetail }) {
  return (
    <Panel title="Investigation timeline">
      {/* The user's traffic around the incident, its window shaded in the severity color (D118). */}
      <div className="rounded-lg border bg-muted/20 p-3">
        <VolumeChart points={d.activity.points} bucketMinutes={d.activity.bucket_minutes} height={120}
                     shade={{ start: d.start_ts, end: d.end_ts, color: SEVERITY_COLORS[d.priority], label: `Incident window (${formatWindow(d.start_ts, d.end_ts)})` }}
                     label={`${d.entities[0]?.name ?? 'User'}'s events around the incident, per ${bucketLabel(d.activity.bucket_minutes)}, UTC`} />
      </div>
      <ol className="relative flex flex-col gap-6 border-l pl-6">
        {d.evidence.map((e, n) => (
          <li key={n} className="relative">
            <span className="absolute top-1.5 -left-[1.95rem] size-3 rounded-full bg-[var(--series-1)]" aria-hidden />
            <p className="text-xs text-muted-foreground tabular-nums">{formatWindow(e.window_start, e.window_end)} UTC</p>
            <p className="font-semibold">{e.name}</p>
            <p className="text-sm text-muted-foreground">{e.reason}</p>
          </li>
        ))}
        <li className="relative">
          <span className="absolute top-1.5 -left-[1.95rem] size-3 rounded-full bg-muted-foreground" aria-hidden />
          <p className="font-semibold">Incident correlated</p>
          <p className="text-sm text-muted-foreground">
            {d.alerts === 1
              ? `1 finding for ${d.entities[0]?.name} became ${d.number}.`
              : `${d.alerts} findings for ${d.entities[0]?.name} within 24 hours were correlated into ${d.number}.`}
          </p>
        </li>
      </ol>
    </Panel>
  )
}

function Entities({ d }: { d: InvestigationDetail }) {
  return (
    <Panel title="Related entities">
      <ul className="grid gap-3 md:grid-cols-2">
        {d.related_entities.map((e) => (
          <li key={`${e.type}-${e.name}`} className="rounded-lg border px-4 py-3">
            <p className="label-caps">{ENTITY_TYPES[e.type]}</p>
            <p className={e.type === 'user' ? 'font-semibold break-all' : 'tech font-semibold break-all'}>
              {e.type === 'user' ? <Link to={userPath(e.name)} className="hover:underline">{e.name}</Link> : e.name}
            </p>
            <p className="text-sm text-muted-foreground">{e.detail}</p>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function Evidence({ d }: { d: InvestigationDetail }) {
  return (
    <Panel title="Detection evidence">
      <ul className="flex flex-col gap-3">
        {d.evidence.map((e, n) => (
          <li key={n} className="flex flex-wrap items-start justify-between gap-3 rounded-lg border px-4 py-3">
            <div className="min-w-0 flex-1">
              <p className="font-semibold">{e.name}</p>
              {/* Log text inside: plain text only. */}
              <p className="text-sm break-words text-muted-foreground">{e.reason}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                {formatWindow(e.window_start, e.window_end)} UTC · {SOURCE_NAMES[e.source]} · score {Math.round(e.score * 100)}
              </p>
            </div>
            <SeverityPill priority={e.level} />
          </li>
        ))}
      </ul>
    </Panel>
  )
}

/** Compact AI analysis (D116): the short summary, then next steps and questions side by side,
 *  the AI boundary as one small line. Log-derived text is rendered as plain text. */
function AiAnalysis({ d }: { d: InvestigationDetail }) {
  const box = 'rounded-lg border bg-muted/30 p-4'
  return (
    <Panel title="Investigation summary">
      <AiAssessment d={d} />
      {d.why_flagged ? (
        <p className="max-w-[75ch] leading-relaxed">{d.why_flagged}</p>
      ) : (
        <p className="text-sm text-muted-foreground">No written summary for this incident.</p>
      )}
      {(d.next_steps.length > 0 || d.next_questions.length > 0) && (
        <div className="grid gap-3 lg:grid-cols-2">
          {d.next_steps.length > 0 && (
            <section className={box} aria-labelledby="next-steps">
              <h3 id="next-steps" className="label-caps mb-3">Next steps</h3>
              <ol className="flex flex-col gap-2.5">
                {d.next_steps.map((step, n) => (
                  <li key={step} className="flex gap-2.5 text-sm">
                    <span aria-hidden className="flex size-5 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground tabular-nums">{n + 1}</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </section>
          )}
          {d.next_questions.length > 0 && (
            <section className={box} aria-labelledby="next-questions">
              <h3 id="next-questions" className="label-caps mb-3">Questions to answer</h3>
              <ul className="flex flex-col gap-2.5">
                {d.next_questions.map((q) => (
                  <li key={q} className="flex gap-2.5 text-sm">
                    <span aria-hidden className="mt-0.5 font-semibold text-muted-foreground">?</span>
                    <span>{q}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
      <CaseSearches d={d} />
      {/* Just the label; how the AI is constrained lives in the README (D124). */}
      {d.narrative_source && <p className="meta"><SourceLabel ai={d.narrative_source === 'ai'} /></p>}
    </Panel>
  )
}
