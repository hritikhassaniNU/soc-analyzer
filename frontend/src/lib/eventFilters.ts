import type { EventFilters } from '@/api/events'
import { RULE_LABELS } from '@/lib/rules'

// Event filters live in the URL (?username=jdoe&flagged=1&start=...), so a filtered view can be
// bookmarked, shared, and linked to from incidents, and the Back button works.
// These two functions convert between URL parameters and the API's filter object.

const TEXT_KEYS = ['username', 'category', 'host'] as const

/** Detection sources for the Logs checkbox filter, in display order. */
export const SOURCE_VALUES = [
  'rule:zscaler_threat', 'rule:high_risk_allowed', 'rule:scripted_client', 'rule:executable_download',
  'window:stat', 'window:ml', 'window:ai',
] as const



/** URL -> API filters. Unknown or malformed values are ignored (the URL is user-editable). */
export function filtersFromParams(params: URLSearchParams): EventFilters {
  const filters: EventFilters = {}
  for (const key of TEXT_KEYS) {
    const value = params.get(key)?.trim()
    if (value) filters[key] = value
  }
  const action = params.get('action')
  if (action === 'Allowed' || action === 'Blocked') filters.action = action
  if (params.get('flagged') === '1') filters.flagged = true
  // Sources checkboxes: ?sources=rule:executable_download,window:stat. Older links
  // (?rule=, ?window=, ?in_window=1) are read into the same list, so they keep working.
  const sources = new Set((params.get('sources') ?? '').split(',').filter((s) => (SOURCE_VALUES as readonly string[]).includes(s)))
  const oldRule = params.get('rule')
  if (oldRule && oldRule in RULE_LABELS) sources.add(`rule:${oldRule}`)
  const oldWindow = params.get('window')
  if (oldWindow === 'stat' || oldWindow === 'ml') sources.add(`window:${oldWindow}`)
  if (params.get('in_window') === '1') { sources.add('window:stat'); sources.add('window:ml') }
  if (sources.size) filters.source = SOURCE_VALUES.filter((s) => sources.has(s)) as EventFilters['source']
  // Filter bar: search, detection source, anomaly.
  const q = params.get('q')?.trim()
  if (q) filters.q = q.slice(0, 200)
  // (No line severity: severity is an incident concept; the Logs filter was removed.)
  if (params.get('anomalous') === '1') filters.anomalous = true
  for (const key of ['start', 'end'] as const) {
    const value = params.get(key)
    if (value && !Number.isNaN(Date.parse(value))) filters[key] = value
  }
  return filters
}

/** API filters -> URL parameters (keeping other parameters such as ?tab=events). */
export function paramsWithFilters(current: URLSearchParams, filters: EventFilters): URLSearchParams {
  const next = new URLSearchParams(current)
  for (const key of [...TEXT_KEYS, 'action', 'flagged', 'in_window', 'rule', 'start', 'end',
    'q', 'severity', 'window', 'anomalous', 'page', 'sources']) next.delete(key)  // new filters: back to page 1
  for (const key of TEXT_KEYS) if (filters[key]) next.set(key, filters[key])
  if (filters.action) next.set('action', filters.action)
  if (filters.flagged) next.set('flagged', '1')
  if (filters.start) next.set('start', filters.start)
  if (filters.end) next.set('end', filters.end)
  if (filters.q) next.set('q', filters.q)
  if (filters.source?.length) next.set('sources', filters.source.join(','))
  if (filters.anomalous) next.set('anomalous', '1')
  return next
}

/** "2026-09-24T11:00" (a datetime-local input, read as UTC) -> "2026-09-24T11:00:00Z". */
export function utcFromInput(value: string): string | undefined {
  return value ? `${value}:00Z` : undefined
}

/** "2026-09-24T11:00:00Z" -> "2026-09-24T11:00" for a datetime-local input (shown as UTC). */
export function inputFromUtc(value: string | undefined): string {
  return value ? new Date(value).toISOString().slice(0, 16) : ''
}

const MINUTE = 60_000

/**
 * Logs-page URL parameters for an incident's drill-down: the upload, its user and time window, rounded
 * OUTWARD to whole minutes. The filter's end is exclusive and its inputs are minute-precision,
 * so an incident ending at 22:05:03 needs end=22:06 to include its own last events.
 */
export function drillDownParams(uploadId: number, username: string, startIso: string, endIso: string): URLSearchParams {
  const start = Math.floor(Date.parse(startIso) / MINUTE) * MINUTE
  const end = (Math.floor(Date.parse(endIso) / MINUTE) + 1) * MINUTE
  const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z')
  return paramsWithFilters(new URLSearchParams({ upload: String(uploadId) }), { username, start: iso(start), end: iso(end) })
}

type CaseSearch = {
  username: string | null; host: string | null; action: string | null; anomalous: boolean
  start: string | null; end: string | null
}

/** Logs-page URL parameters for one of a case's next-step searches. The backend already
 *  rounded the window outward to minutes; times are normalized to "…Z". */
export function caseSearchParams(uploadId: number, s: CaseSearch): URLSearchParams {
  const z = (value: string | null) => (value ? iso(Date.parse(value)) : undefined)
  return paramsWithFilters(new URLSearchParams({ upload: String(uploadId) }), {
    username: s.username ?? undefined, host: s.host ?? undefined,
    action: s.action === 'Allowed' || s.action === 'Blocked' ? s.action : undefined,
    anomalous: s.anomalous || undefined, start: z(s.start), end: z(s.end),
  })
}

const DAY = 86_400_000
const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z')

/** Time-range presets counted back from NOW: "last 3 days" means what it
 *  says. Rounded to the minute; the end is exclusive, one minute after now. */
export function timePresets(nowMs: number = Date.now()) {
  const afterNow = (Math.floor(nowMs / MINUTE) + 1) * MINUTE
  const back = (days: number, label: string) => ({ label, start: iso(afterNow - days * DAY), end: iso(afterNow) })
  return { last_24h: back(1, 'Last 24 hours'), last_3d: back(3, 'Last 3 days'), last_7d: back(7, 'Last 7 days') }
}
export type TimePreset = keyof ReturnType<typeof timePresets>
