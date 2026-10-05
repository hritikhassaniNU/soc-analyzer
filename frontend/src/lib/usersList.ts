import type { UserListItem } from '@/api/users'

/** Severity buckets for the Users list: a user's worst unresolved case, or "none". */
export const USER_SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const
export type UserSeverity = (typeof USER_SEVERITIES)[number]
export const SORT_KEYS = ['risk', 'open_cases', 'events', 'last_seen'] as const
export type SortKey = (typeof SORT_KEYS)[number]

export type UserListFilters = {
  severities: UserSeverity[] // empty = all
  departments: string[] // empty = all (several can be checked)
  openOnly: boolean
  sort: SortKey
  dir: 'desc' | 'asc' // click the same header again to flip
}

export const severityOfUser = (u: UserListItem): UserSeverity => u.priority ?? 'none'

/** URL <-> filters (?severity=critical,high&dept=Finance,HR&open=1&sort=events). The dashboard's
 *  older ?risk=high link means critical + high. Unknown values are ignored. */
export function userFiltersFrom(params: URLSearchParams): UserListFilters {
  const raw = params.get('severity') ?? (params.get('risk') === 'high' ? 'critical,high' : '')
  const severities = raw.split(',').filter((s): s is UserSeverity => (USER_SEVERITIES as readonly string[]).includes(s))
  const sort = params.get('sort')
  return {
    severities,
    departments: (params.get('dept') ?? '').split(',').map((d) => d.trim()).filter(Boolean),
    openOnly: params.get('open') === '1',
    sort: (SORT_KEYS as readonly string[]).includes(sort ?? '') ? (sort as SortKey) : 'risk',
    dir: params.get('dir') === 'asc' ? 'asc' : 'desc',
  }
}

export function applyUserFilters(users: UserListItem[], f: UserListFilters): UserListItem[] {
  const shown = users.filter((u) =>
    (f.severities.length === 0 || f.severities.includes(severityOfUser(u)))
    && (f.departments.length === 0 || (u.department !== null && f.departments.includes(u.department)))
    && (!f.openOnly || u.open_cases > 0))
  const value = (u: UserListItem): number | null =>
    f.sort === 'risk' ? u.risk : f.sort === 'open_cases' ? u.open_cases
      : f.sort === 'events' ? u.events : Date.parse(u.last_seen)
  const sign = f.dir === 'asc' ? 1 : -1
  // Users without a value (no open risk) stay last in both directions; ties by name (stable order).
  return [...shown].sort((a, b) => {
    const va = value(a)
    const vb = value(b)
    if (va === null || vb === null) return va === vb ? a.username.localeCompare(b.username) : va === null ? 1 : -1
    return sign * (va - vb) || a.username.localeCompare(b.username)
  })
}

export function severityCounts(users: UserListItem[]): Record<UserSeverity, number> {
  const counts = Object.fromEntries(USER_SEVERITIES.map((s) => [s, 0])) as Record<UserSeverity, number>
  for (const u of users) counts[severityOfUser(u)] += 1
  return counts
}

/** "jdoe" -> "JD", "a.miller" -> "AM": the avatar's initials. */
export function initials(username: string): string {
  const parts = username.split(/[._\-\s@]+/).filter(Boolean)
  return (parts.length > 1 ? parts[0][0] + parts[1][0] : username.slice(0, 2)).toUpperCase()
}

export { paginate, PAGE_SIZE as USERS_PAGE_SIZE } from '@/lib/pagination'
