import { Link } from 'react-router'
import type { RiskyUser } from '@/api/dashboard'
import RiskMeter from '@/components/RiskMeter'
import { userPath } from '@/lib/users'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PRIORITY_META } from '@/lib/incidents'

function SeverityIcon({ priority }: { priority: RiskyUser['priority'] }) {
  const { label, icon: Icon, iconClass } = PRIORITY_META[priority]
  return <Icon className={`size-3.5 shrink-0 ${iconClass}`} aria-label={label} />
}

/** "Who do I look at first?": the users whose worst incident ranks highest, with why. */
export default function RiskyUsers({ users, total }: { users: RiskyUser[]; total: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Users at highest risk</CardTitle>
      </CardHeader>
      <CardContent>
        {users.length === 0 ? (
          <p className="text-sm text-muted-foreground">No user has a medium, high or critical incident.</p>
        ) : (
          <ol className="divide-y rounded-md border">
            {users.map((u, n) => (
              <li key={u.username}>
                {/* Compact: name + one truncated reason line; counts on hover. */}
                <Link to={userPath(u.username)} title={`${u.reason} · ${u.incidents} incident${u.incidents === 1 ? '' : 's'} · ${u.findings} finding${u.findings === 1 ? '' : 's'}`}
                      className="flex items-center gap-3 px-3 py-2 hover:bg-muted/50">
                  <span className="w-4 text-sm text-muted-foreground tabular-nums">{n + 1}</span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1.5 font-medium">
                      <SeverityIcon priority={u.priority} /> <span className="truncate">{u.username}</span>
                    </span>
                    <span className="block truncate text-sm text-muted-foreground">{u.reason}</span>
                  </span>
                  <RiskMeter risk={Math.round(u.priority_score * 100)} priority={u.priority} width="w-12" />
                </Link>
              </li>
            ))}
          </ol>
        )}
        {total > users.length && (
          <Link to="/users?severity=critical,high,medium" className="mt-3 inline-block text-sm text-muted-foreground underline-offset-2 hover:underline">
            +{total - users.length} more user{total - users.length === 1 ? '' : 's'} at medium or higher risk → Users
          </Link>
        )}
      </CardContent>
    </Card>
  )
}
