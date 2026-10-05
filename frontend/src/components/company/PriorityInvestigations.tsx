import { ArrowRight } from 'lucide-react'
import { Link } from 'react-router'
import type { DashboardIncident } from '@/api/dashboard'
import RiskMeter from '@/components/RiskMeter'
import { PriorityLabel } from '@/components/incidents/IncidentsPanel'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatWindow } from '@/lib/incidents'

/** The five incidents to open first ("what story", where the users list says "who"). */
export default function PriorityInvestigations({ incidents }: { incidents: DashboardIncident[] }) {
  return (
    <Card>
      <CardHeader className="flex items-center justify-between gap-2">
        <CardTitle>Priority investigations</CardTitle>
        <Link to="/investigations?status=unresolved" className="text-sm text-muted-foreground hover:text-foreground">View all →</Link>
      </CardHeader>
      <CardContent>
        {incidents.length === 0 ? (
          <p className="text-sm text-muted-foreground">No incidents yet.</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {incidents.map((i) => (
              <li key={i.id}>
                <Link to={i.case_id ? `/investigations/${i.case_id}` : '/investigations'} className="flex items-start gap-3 px-3 py-2.5 hover:bg-muted/50">
                  <span className="w-24 shrink-0 text-sm"><PriorityLabel priority={i.priority} /></span>
                  <span className="min-w-0 flex-1 text-sm">
                    <span className="font-medium">{i.username}</span>{' '}
                    <span className="text-muted-foreground">· {formatWindow(i.start_ts, i.end_ts)} UTC</span>
                    <span className="block text-muted-foreground">{i.title} · {i.findings} finding{i.findings === 1 ? '' : 's'}</span>
                  </span>
                  <span className="text-sm"><RiskMeter risk={Math.round(i.priority_score * 100)} priority={i.priority} width="w-12" /></span>
                  <ArrowRight className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
