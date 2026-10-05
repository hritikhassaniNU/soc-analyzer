import { Link } from 'react-router'
import { useDashboard } from '@/api/dashboard'
import AiReviewBanner from '@/components/company/AiReviewBanner'
import IncidentTimeline from '@/components/company/IncidentTimeline'
import KpiTiles from '@/components/company/KpiTiles'
import PriorityInvestigations from '@/components/company/PriorityInvestigations'
import RiskBreakdown from '@/components/company/RiskBreakdown'
import RiskyEntities from '@/components/company/RiskyEntities'
import RiskyUsers from '@/components/company/RiskyUsers'
import { Button } from '@/components/ui/button'

/** The company-wide view: every completed upload, each incident counted once. */
export default function DashboardPage() {
  const dashboard = useDashboard()
  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="page-title">Dashboard</h1>
        {dashboard.data && dashboard.data.kpis.uploads > 0 && (
          <p className="page-subtitle">
            All uploads: {dashboard.data.kpis.datasets} dataset{dashboard.data.kpis.datasets === 1 ? '' : 's'} from{' '}
            {dashboard.data.kpis.uploads} upload{dashboard.data.kpis.uploads === 1 ? '' : 's'}; repeated incidents are counted once.
          </p>
        )}
      </div>
      {dashboard.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
      {dashboard.isError && (
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          Can't load the dashboard.
          <Button variant="outline" size="sm" onClick={() => dashboard.refetch()}>Retry</Button>
        </div>
      )}
      {dashboard.data && dashboard.data.kpis.uploads === 0 && (
        <p className="text-sm text-muted-foreground">
          No analyzed uploads yet. <Link to="/uploads" className="underline">Upload a log file</Link> to start.
        </p>
      )}
      {dashboard.data && dashboard.data.kpis.uploads > 0 && (
        <>
          {/* Calm order: numbers, one AI line, charts, what to work on, compact context. */}
          <KpiTiles kpis={dashboard.data.kpis} datasets={dashboard.data.datasets} />
          <AiReviewBanner />
          {/* Stretch: both chart cards share one height, no black gap under the shorter one. */}
          <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
            <IncidentTimeline timeline={dashboard.data.timeline} />
            <RiskBreakdown severity={dashboard.data.severity} categories={dashboard.data.categories} />
          </div>
          {/* Two balanced columns: work queue + entities left, people right. */}
          <div className="grid items-start gap-6 lg:grid-cols-[2fr_1fr]">
            <div className="flex flex-col gap-6">
              <PriorityInvestigations incidents={dashboard.data.top_incidents} />
              <RiskyEntities entities={dashboard.data.top_entities} />
            </div>
            <RiskyUsers users={dashboard.data.users_at_risk} total={dashboard.data.kpis.affected_users} />
          </div>
        </>
      )}
    </main>
  )
}
