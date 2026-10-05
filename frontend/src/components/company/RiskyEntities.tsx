import { Link } from 'react-router'
import type { Dashboard } from '@/api/dashboard'
import RiskMeter from '@/components/RiskMeter'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { priorityForRisk } from '@/lib/incidents'
import { userPath } from '@/lib/users'

const GROUPS = [['user', 'Users'], ['ip', 'IPs'], ['domain', 'Domains']] as const

/** Where each entity leads: a user's profile; an IP or domain opens the cases it appears in
 *  (case search covers entities). */
const entityPath = (e: Dashboard['top_entities'][number]) =>
  e.type === 'user' ? userPath(e.name) : `/investigations?q=${encodeURIComponent(e.name)}`

/** Users, source IPs and domains, ranked by the highest incident they appear in. Grouped by type:
 *  each heading once, then compact clickable rows. */
export default function RiskyEntities({ entities }: { entities: Dashboard['top_entities'] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Highest-risk entities</CardTitle>
      </CardHeader>
      <CardContent>
        {entities.length === 0 ? (
          <p className="text-sm text-muted-foreground">None in medium, high or critical incidents.</p>
        ) : (
          <div className="grid gap-x-6 gap-y-4 sm:grid-cols-3">
            {GROUPS.map(([type, label]) => {
              const rows = entities.filter((e) => e.type === type)
              return (
                <section key={type} aria-label={label}>
                  <h3 className="label-caps mb-1">{label}</h3>
                  {rows.length === 0 ? <p className="py-2 text-sm text-muted-foreground">None</p> : (
                    <ul className="divide-y">
                      {rows.map((e) => (
                        <li key={e.name}>
                          <Link to={entityPath(e)} title={e.type === 'user' ? `${e.name}: user profile` : `Cases involving ${e.name}`}
                                className="group flex items-center gap-3 py-2 text-sm">
                            {/* Domains are attacker-controlled text: plain text only. */}
                            <span className={`min-w-0 flex-1 truncate group-hover:underline ${e.type === 'user' ? 'font-medium' : 'tech'}`}>{e.name}</span>
                            <RiskMeter risk={e.risk} priority={priorityForRisk(e.risk)} width="w-10" />
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
