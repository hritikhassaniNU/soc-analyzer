import { describe, expect, it } from 'vitest'
import type { UserListItem } from '@/api/users'
import { applyUserFilters, initials, paginate, severityCounts, userFiltersFrom } from '@/lib/usersList'

const u = (username: string, priority: UserListItem['priority'], risk: number | null, extra: Partial<UserListItem> = {}): UserListItem => ({
  username, department: 'Finance', risk, priority, open_cases: risk === null ? 0 : 1, cases: 1, events: 100,
  last_seen: '2026-09-27T10:00:00Z', reason: null, ...extra,
})
const users = [u('jdoe', 'critical', 100), u('amiller', 'high', 90, { department: 'Sales', events: 900 }),
  u('esmith', 'low', 38), u('quiet', null, null, { events: 5000 })]

describe('users list', () => {
  it('reads filters from the URL; the old ?risk=high means critical + high', () => {
    expect(userFiltersFrom(new URLSearchParams('risk=high')).severities).toEqual(['critical', 'high'])
    expect(userFiltersFrom(new URLSearchParams('severity=low,bogus&dept=HR,Sales&open=1&sort=events')))
      .toEqual({ severities: ['low'], departments: ['HR', 'Sales'], openOnly: true, sort: 'events', dir: 'desc' })
  })

  it('filters by severity, department and open cases, and sorts', () => {
    const base = { severities: [], departments: [], openOnly: false, sort: 'risk' as const, dir: 'desc' as const }
    expect(applyUserFilters(users, base).map((x) => x.username)).toEqual(['jdoe', 'amiller', 'esmith', 'quiet'])
    expect(applyUserFilters(users, { ...base, severities: ['none'] }).map((x) => x.username)).toEqual(['quiet'])
    expect(applyUserFilters(users, { ...base, departments: ['Sales'] }).map((x) => x.username)).toEqual(['amiller'])
    expect(applyUserFilters(users, { ...base, departments: ['Sales', 'Finance'] })).toHaveLength(4)
    expect(applyUserFilters(users, { ...base, openOnly: true })).toHaveLength(3)
    expect(applyUserFilters(users, { ...base, sort: 'events' })[0].username).toBe('quiet')
  })

  it('counts each severity bucket and makes initials', () => {
    expect(severityCounts(users)).toEqual({ critical: 1, high: 1, medium: 0, low: 1, none: 1 })
    expect([initials('jdoe'), initials('a.miller'), initials('x')]).toEqual(['JD', 'AM', 'X'])
  })
})

describe('paginate', () => {
  const list = Array.from({ length: 41 }, (_, i) => i + 1)
  it('splits into pages of 25 and reports the range', () => {
    expect(paginate(list, 1)).toMatchObject({ page: 1, pages: 2, from: 1, to: 25, total: 41 })
    expect(paginate(list, 2).items).toEqual(list.slice(25))
    expect(paginate(list, 2)).toMatchObject({ from: 26, to: 41 })
  })
  it('clamps out-of-range or broken page numbers', () => {
    expect(paginate(list, 99).page).toBe(2)
    expect(paginate(list, 0).page).toBe(1)
    expect(paginate(list, Number.NaN).page).toBe(1)
    expect(paginate([], 3)).toMatchObject({ page: 1, pages: 1, from: 0, to: 0 })
  })
})

describe('sort direction (D109)', () => {
  it('flips with dir=asc and keeps users without a risk last', () => {
    const f = { severities: [], departments: [], openOnly: false, sort: 'risk' as const }
    expect(applyUserFilters(users, { ...f, dir: 'asc' }).map((x) => x.username)).toEqual(['esmith', 'amiller', 'jdoe', 'quiet'])
    expect(applyUserFilters(users, { ...f, dir: 'desc' }).map((x) => x.username)).toEqual(['jdoe', 'amiller', 'esmith', 'quiet'])
    expect(applyUserFilters(users, { ...f, sort: 'events', dir: 'asc' })[0].events).toBe(100)
    expect(userFiltersFrom(new URLSearchParams('sort=events&dir=asc')).dir).toBe('asc')
  })
})
