import { ArrowLeft, ArrowRight, Building2, Laptop, type LucideIcon, MapPin, ScrollText } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { type UserProfile, useGenerateUserReview, useUserProfile, useUserReview } from '@/api/users'
import Pagination from '@/components/Pagination'
import { ReviewCard } from '@/components/company/AiReview'
import UserActivityChart from '@/components/users/UserActivityChart'
import { SeverityPill } from '@/components/investigations/Labels'
import { Button } from '@/components/ui/button'
import { formatBytes, formatUtc } from '@/lib/format'
import { formatWindow, SEVERITY_COLORS } from '@/lib/incidents'
import { STATUS_LABELS, VERDICT_LABELS } from '@/lib/investigations'
import { paginate } from '@/lib/pagination'
import { initials } from '@/lib/usersList'
import NotFoundPage from '@/pages/NotFoundPage'

export default function UserProfilePage() {
  const { username } = useParams()
  if (!username) return <NotFoundPage />
  return <Profile username={username} />
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-xl border bg-card p-6">
      <h2 className="section-title">{title}</h2>
      {children}
    </section>
  )
}

function Profile({ username }: { username: string }) {
  const profile = useUserProfile(username)
  const p = profile.data

  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <Link to="/users" className="flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> All users
      </Link>
      {profile.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
      {profile.isError && <p className="text-sm text-muted-foreground">This user isn't in any scanned upload.</p>}
      {p && (
        <>
          <Header p={p} />
          <div className="grid items-start gap-6 lg:grid-cols-[1.4fr_1fr]">
            <div className="flex flex-col gap-6">
              <Cases p={p} />
              <UserActivityChart activity={p.activity} />
            </div>
            <div className="flex flex-col gap-6">
              <UserReview username={p.username} />
              <VerdictHistory p={p} />
              <Behavior p={p} />
            </div>
          </div>
        </>
      )}
    </main>
  )
}

/** Profile header (D93): identity on the left, current risk on the right, the explanation as a
 *  callout with a button to the case that sets it, a stat strip, then devices and IPs with their
 *  share of the user's events. Log times in UTC like the rest of the app. */
function Header({ p }: { p: UserProfile }) {
  const stats: [string, string][] = [
    ['Events', p.events.toLocaleString()],
    ['Datasets', String(p.datasets)],
    ['First seen', formatUtc(p.first_seen)],
    ['Last seen', formatUtc(p.last_seen)],
  ]
  return (
    <section className="flex flex-col gap-5 rounded-xl border bg-card p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-center gap-4">
          <span aria-hidden className="flex size-14 shrink-0 items-center justify-center rounded-full bg-primary/15 text-lg font-semibold text-primary ring-1 ring-primary/30">
            {initials(p.username)}
          </span>
          <div className="flex min-w-0 flex-col gap-2">
            <h1 className="page-title break-all">{p.username}</h1>
            {/* Identity facts as labeled chips (D93): readable at a glance, not a grey subtitle. */}
            <ul className="flex flex-wrap gap-2 text-sm">
              <IdentityChip icon={Building2} label="Department" value={p.department} />
              <IdentityChip icon={MapPin} label="Location" value={p.location} />
              <IdentityChip icon={Laptop} label="Devices" value={p.devices.length ? String(p.devices.length) : null} />
            </ul>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          {p.risk.priority ? <SeverityPill priority={p.risk.priority} /> : <span className="meta">No open risk</span>}
          {p.risk.score !== null && p.risk.priority && (
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-24 rounded-full bg-muted" aria-hidden>
                <div className="h-1.5 rounded-full" style={{ width: `${p.risk.score}%`, background: SEVERITY_COLORS[p.risk.priority] }} />
              </div>
              <span className="text-sm">Risk <b className="tabular-nums">{p.risk.score}</b></span>
            </div>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/40 px-4 py-3">
        <p className="text-sm text-muted-foreground">{p.risk.explanation}</p>
        {p.risk.case_id && (
          <Button asChild size="sm" variant="outline">
            <Link to={`/investigations/${p.risk.case_id}`}>Open INC-{p.risk.case_id} <ArrowRight /></Link>
          </Button>
        )}
      </div>

      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map(([label, value]) => (
          <div key={label} className="rounded-lg border px-4 py-3">
            <dt className="label-caps">{label}</dt>
            <dd className="mt-1 font-semibold tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>

      <div className="grid gap-6 md:grid-cols-2">
        <ShareList title="Devices" total={p.events} empty="None in the logs (no Client Connector data)"
                   items={p.devices.map((d) => ({ name: d.name, detail: d.os, count: d.events }))} />
        <ShareList title="IPs" total={p.events} empty="None"
                   items={p.ips.map((ip) => ({ name: ip.name, detail: null, count: ip.count }))} />
      </div>
    </section>
  )
}

function IdentityChip({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string | null }) {
  return (
    <li className="inline-flex items-center gap-1.5 rounded-md border bg-muted/40 px-2.5 py-1">
      <Icon className="size-4 text-muted-foreground" aria-hidden />
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value ?? '—'}</span>
    </li>
  )
}

/** Name (mono, log value) + optional detail, its event count and a thin bar for its share. */
function ShareList({ title, items, total, empty }: {
  title: string; items: { name: string; detail: string | null; count: number }[]; total: number; empty: string
}) {
  return (
    <div>
      <h2 className="label-caps mb-2">{title}</h2>
      {items.length === 0 ? <p className="meta">{empty}</p> : (
        <ul className="flex flex-col gap-2.5">
          {items.map((i) => (
            <li key={i.name} className="flex flex-col gap-1 text-sm">
              <div className="flex items-baseline justify-between gap-3">
                <span className="min-w-0 truncate"><span className="tech">{i.name}</span>
                  {i.detail && <span className="text-muted-foreground"> · {i.detail}</span>}</span>
                <span className="shrink-0 tabular-nums text-muted-foreground">{i.count.toLocaleString()} events</span>
              </div>
              <div className="h-1 rounded-full bg-muted" aria-hidden>
                <div className="h-1 rounded-full bg-[var(--series-1)]" style={{ width: `${total ? Math.max((i.count / total) * 100, 1) : 0}%` }} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Cases({ p }: { p: UserProfile }) {
  const [page, setPage] = useState(1)
  const paged = paginate(p.cases, page, 10) // 10 per page inside the profile column (D95)
  return (
    <Panel title={`Cases (${p.cases.length})`}>
      {p.cases.length === 0 ? <p className="text-sm text-muted-foreground">No incidents for this user.</p> : (
        <ul className="flex flex-col gap-2">
          {paged.items.map((c) => (
            <li key={c.id}>
              <Link to={`/investigations/${c.id}`} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3 hover:bg-muted/50">
                <div className="min-w-0">
                  <p className="font-semibold">{c.number} · {c.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatWindow(c.start_ts, c.end_ts)} UTC · Risk {c.risk} · {STATUS_LABELS[c.status]}
                    {c.verdict && ` · ${VERDICT_LABELS[c.verdict as keyof typeof VERDICT_LABELS]}`}
                    {c.owner && ` · ${c.owner}`}
                  </p>
                </div>
                <SeverityPill priority={c.priority} />
              </Link>
            </li>
          ))}
        </ul>
      )}
      {paged.pages > 1 && (
        <Pagination page={paged.page} pages={paged.pages} from={paged.from} to={paged.to} total={paged.total}
                    noun="cases" onPage={setPage} />
      )}
    </Panel>
  )
}

function UserReview({ username }: { username: string }) {
  return (
    <ReviewCard
      title="AI summary"
      review={useUserReview(username)}
      generate={useGenerateUserReview(username)}
      empty="No summary yet. It describes this user's incidents across all scanned logs, earlier verdicts, and what to check next."
    />
  )
}

function VerdictHistory({ p }: { p: UserProfile }) {
  const rows: [string, number][] = [
    ['Unresolved', p.verdicts.unresolved],
    [VERDICT_LABELS.true_positive, p.verdicts.true_positive],
    [VERDICT_LABELS.false_positive, p.verdicts.false_positive],
    [VERDICT_LABELS.benign, p.verdicts.benign],
  ]
  return (
    <Panel title="Verdict history">
      <dl className="grid grid-cols-2 gap-3 text-sm">
        {rows.map(([label, n]) => (
          <div key={label} className="rounded-lg border px-3 py-2">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="metric">{n}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  )
}

function Behavior({ p }: { p: UserProfile }) {
  const b = p.baseline
  const peak = Math.max(...b.hours_utc, 1)
  return (
    <Panel title="Behavior baseline">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm">
        <dt className="text-muted-foreground">Active days</dt><dd>{b.active_days}</dd>
        <dt className="text-muted-foreground">Typical day</dt><dd>{b.median_daily_events.toLocaleString()} events</dd>
        <dt className="text-muted-foreground">Sent per day</dt><dd>{formatBytes(b.median_daily_bytes_out)} typical · {formatBytes(b.max_daily_bytes_out)} max</dd>
        <dt className="text-muted-foreground">Blocked</dt><dd>{(b.blocked_share * 100).toFixed(1)}% of requests</dd>
      </dl>
      <div>
        <p className="text-sm text-muted-foreground">Activity by hour of day (UTC)</p>
        {/* Plain bars; the exact count is in each bar's label for screen readers and on hover. */}
        <div className="mt-2 flex h-16 items-end gap-0.5" role="img" aria-label="Events per hour of day, UTC">
          {b.hours_utc.map((n, hour) => (
            <div key={hour} title={`${String(hour).padStart(2, '0')}:00 UTC · ${n.toLocaleString()} events`}
                 className="flex-1 rounded-t-sm bg-[var(--series-1)]" style={{ height: `${Math.max((n / peak) * 100, n ? 4 : 0)}%` }} />
          ))}
        </div>
        <div className="flex justify-between text-xs text-muted-foreground tabular-nums"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>
      </div>
      <div className="grid gap-4 text-sm sm:grid-cols-2">
        <TopList title="Top domains" items={b.top_domains} mono />
        <TopList title="Top URL categories" items={b.top_categories} />
      </div>
      <Button asChild variant="outline" size="sm" className="w-fit">
        {/* Logs shows one upload at a time: open the one with this user's newest case, if any. */}
        <Link to={`/logs?${new URLSearchParams({ ...(p.cases[0] ? { upload: String(p.cases[0].upload_id) } : {}), username: p.username })}`}>
          <ScrollText /> View this user's events
        </Link>
      </Button>
    </Panel>
  )
}

function TopList({ title, items, mono = false }: { title: string; items: UserProfile['baseline']['top_domains']; mono?: boolean }) {
  return (
    <div>
      <p className="text-muted-foreground">{title}</p>
      <ol className="mt-1 flex flex-col gap-0.5">
        {items.map((i) => (
          // Domains are log text: plain text, truncated with the full name on hover.
          <li key={i.name} className="flex justify-between gap-2"><span className={mono ? 'tech truncate' : 'truncate'} title={i.name}>{i.name}</span><span className="text-muted-foreground tabular-nums">{i.count.toLocaleString()}</span></li>
        ))}
      </ol>
    </div>
  )
}
