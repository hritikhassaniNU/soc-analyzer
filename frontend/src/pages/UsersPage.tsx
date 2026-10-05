import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useUsers } from '@/api/users'
import { SeverityPill } from '@/components/investigations/Labels'
import RiskByDepartment from '@/components/users/RiskByDepartment'
import MultiSelect from '@/components/MultiSelect'
import Pagination from '@/components/Pagination'
import RiskMeter from '@/components/RiskMeter'
import SortHeader from '@/components/SortHeader'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { capitalizeEach, formatUtc } from '@/lib/format'
import { severityOptions } from '@/lib/incidents'
import { userPath } from '@/lib/users'
import {
  applyUserFilters, initials, paginate, severityCounts, type SortKey, userFiltersFrom,
} from '@/lib/usersList'
import { cn } from '@/lib/utils'

const toggle = <T,>(list: readonly T[], value: T): T[] => list.includes(value) ? list.filter((v) => v !== value) : [...list, value]

/** Everyone seen in the logs: severity chips with counts, department and open-case filters,
 *  sortable columns, and rows that say why a user is risky. Every filter lives in the URL. */
export default function UsersPage() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q')?.trim() ?? ''
  const [search, setSearch] = useState(q)
  const users = useUsers(q)
  const navigate = useNavigate()
  const f = userFiltersFrom(params)

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params)
    next.delete('risk') // the dashboard's older link; ?severity= replaces it
    if (key !== 'page') next.delete('page') // a new filter or sort starts again at page 1
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next)
  }

  // Same column again flips the direction; a new column starts highest first.
  function sortBy(key: SortKey) {
    const next = new URLSearchParams(params)
    next.delete('page')
    const dir = key === f.sort && f.dir === 'desc' ? 'asc' : 'desc'
    if (key === 'risk') next.delete('sort')
    else next.set('sort', key)
    if (dir === 'asc') next.set('dir', 'asc')
    else next.delete('dir')
    setParams(next)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    setParam('q', search.trim())
  }

  const all = users.data ?? []
  const counts = severityCounts(all)
  const departments = [...new Set(all.map((u) => u.department).filter((d): d is string => !!d))].sort()
  const shown = applyUserFilters(all, f)
  const paged = paginate(shown, Number(params.get('page') ?? '1'))
  const filtered = f.severities.length > 0 || f.departments.length > 0 || f.openOnly || !!q

  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="page-title">Users</h1>
        <p className="page-subtitle">
          Everyone seen in the scanned logs. Risk is the highest risk among a user's unresolved cases.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <form onSubmit={submit} role="search">
            <Input aria-label="Search users" placeholder="Search users…" value={search}
                   onChange={(e) => setSearch(e.target.value)} className="h-9 w-64" />
          </form>
          <MultiSelect label="Severity" allLabel="All severity" selected={f.severities}
                       options={severityOptions(counts, { value: 'none', label: 'No open risk' })}
                       onChange={(v) => setParam('severity', v.join(','))} />
          <MultiSelect label="Department" allLabel="All departments" selected={f.departments}
                       options={departments.map((d) => ({ value: d, label: d, count: all.filter((u) => u.department === d).length }))}
                       onChange={(v) => setParam('dept', v.join(','))} />
          {/* Segmented like Logs' "All events | Anomalies only". */}
          <div role="group" aria-label="Open cases" className="inline-flex rounded-lg border p-0.5">
            {([[false, 'All users'], [true, 'With open cases']] as const).map(([value, label]) => (
              <button key={label} type="button" aria-pressed={f.openOnly === value} onClick={() => setParam('open', value ? '1' : '')}
                      className={cn('rounded-md px-3 py-1 text-sm', f.openOnly === value
                        ? 'bg-accent font-medium text-accent-foreground' : 'text-muted-foreground hover:text-foreground')}>
                {label}
              </button>
            ))}
          </div>
          {filtered && (
            <button type="button" className="h-9 px-2 text-sm text-muted-foreground hover:text-foreground"
                    onClick={() => { setSearch(''); setParams(new URLSearchParams()) }}>
              Clear filters
            </button>
          )}
          <span className="meta ml-auto">{shown.length} of {all.length} users</span>
        </div>
      </div>

      {/* Follows every filter except department, which it sets. */}
      {users.data && (
        <RiskByDepartment users={applyUserFilters(all, { ...f, departments: [] })} departments={f.departments} severities={f.severities}
                          onToggleDepartment={(d) => setParam('dept', toggle(f.departments, d).join(','))}
                          onToggleSeverity={(sv) => setParam('severity', toggle(f.severities, sv).join(','))} />
      )}
      {users.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
      {users.isError && <p className="text-sm text-muted-foreground">Couldn't load users. Try again.</p>}
      {users.data && (shown.length === 0 ? (
        <p className="text-sm text-muted-foreground">{filtered ? 'No users match these filters.' : 'No scanned logs yet.'}</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Severity</TableHead>
                <SortHeader label="Risk" active={f.sort === 'risk'} dir={f.dir} onSort={() => sortBy('risk')} />
                <SortHeader label="Open cases" active={f.sort === 'open_cases'} dir={f.dir} onSort={() => sortBy('open_cases')} align="right" />
                <SortHeader label="Events" active={f.sort === 'events'} dir={f.dir} onSort={() => sortBy('events')} align="right" />
                <SortHeader label="Last seen (UTC)" active={f.sort === 'last_seen'} dir={f.dir} onSort={() => sortBy('last_seen')} />
                {/* Last and w-full: takes the spare width, so short reasons leave no gap mid-row. */}
                <TableHead className="w-full">Why</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paged.items.map((u) => (
                <TableRow key={u.username} className="cursor-pointer" onClick={() => navigate(userPath(u.username))}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <span aria-hidden className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold">
                        {initials(u.username)}
                      </span>
                      <div className="min-w-0">
                        <Link to={userPath(u.username)} className="font-semibold hover:underline" onClick={(e) => e.stopPropagation()}>
                          {u.username}
                        </Link>
                        <p className="meta">{u.department ?? '—'}</p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>{u.priority ? <SeverityPill priority={u.priority} /> : <span className="meta">No open risk</span>}</TableCell>
                  <TableCell>
                    {u.risk === null || !u.priority ? <span className="text-muted-foreground">—</span> : (
                      <RiskMeter risk={u.risk} priority={u.priority} width="w-20" />
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {u.open_cases}<span className="text-muted-foreground"> / {u.cases}</span>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{u.events.toLocaleString()}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">
                    <time dateTime={u.last_seen}>{formatUtc(u.last_seen)}</time>
                  </TableCell>
                  <TableCell className="min-w-56 whitespace-normal text-muted-foreground">{u.reason ? capitalizeEach(u.reason) : '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {paged.pages > 1 && (
            <div className="border-t px-4 py-3">
              <Pagination page={paged.page} pages={paged.pages} from={paged.from} to={paged.to} total={paged.total}
                          noun="users" onPage={(n) => setParam('page', n === 1 ? '' : String(n))} />
            </div>
          )}
        </div>
      ))}
    </main>
  )
}
