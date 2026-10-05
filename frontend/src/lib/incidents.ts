import { CircleAlert, CircleDot, OctagonAlert, TriangleAlert, type LucideIcon } from 'lucide-react'
import type { Priority } from '@/api/incidents'
import { RULE_LABELS } from '@/lib/rules'

/** Each priority: a word, an icon and a color. Never color alone (colorblind users, print). */
export const PRIORITY_META: Record<Priority, { label: string; icon: LucideIcon; iconClass: string }> = {
  critical: { label: 'Critical', icon: OctagonAlert, iconClass: 'text-priority-critical' },
  high: { label: 'High', icon: TriangleAlert, iconClass: 'text-priority-high' },
  medium: { label: 'Medium', icon: CircleAlert, iconClass: 'text-priority-medium' },
  low: { label: 'Low', icon: CircleDot, iconClass: 'text-priority-low' },
}

export const PRIORITY_ORDER: Priority[] = ['critical', 'high', 'medium', 'low']

/** Fill colors for severity in charts: the reserved priority colors (low = teal). Never
 *  color alone: charts repeat every label with its number (legend, table view). */
export const SEVERITY_COLORS: Record<Priority, string> = {
  critical: 'var(--priority-critical)',
  high: 'var(--priority-high)',
  medium: 'var(--priority-medium)',
  low: 'var(--priority-low)',
}

/** Human names for finding kinds: the four rules plus the statistical detectors. */
export const KIND_LABELS: Record<string, string> = {
  ...RULE_LABELS,
  request_burst: 'Request burst',
  large_upload: 'Large upload',
  off_hours: 'Unusual hours',
  beaconing: 'Beaconing',
  rare_domain: 'Rare random-looking domain',
  behavioral_outlier: 'Unusual combination (ML)',
  ai_suspicious_domain: 'Suspicious domain (AI)',
}

export function kindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind
}

/** Shown behind the info button next to every score (the brief's "confidence score"). */
export const SCORE_HELP =
  'A heuristic ranking score from 0 to 1: the strongest finding weighted by how serious its kind ' +
  'is, plus a bonus for each other independent kind of evidence about the same user. It ranks ' +
  'what to look at first; it is not the probability that the user is compromised.'

const day = new Intl.DateTimeFormat(undefined, {
  weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC',
})
const time = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC',
})

/** "Tue, 22 Sep 14:05–22:05" or "Thu, 24 Sep 13:17 – Fri, 25 Sep 13:04" (UTC, like the events table). */
export function formatWindow(startIso: string, endIso: string): string {
  const start = new Date(startIso)
  const end = new Date(endIso)
  const startDay = day.format(start)
  const endDay = day.format(end)
  if (startDay === endDay) {
    const endTime = time.format(end)
    const startTime = time.format(start)
    return startTime === endTime ? `${startDay} ${startTime}` : `${startDay} ${startTime}–${endTime}`
  }
  return `${startDay} ${time.format(start)} – ${endDay} ${time.format(end)}`
}

/** "14:05" (UTC), for findings inside an incident. */
export function formatTime(iso: string): string {
  return time.format(new Date(iso))
}

/** Which layer produced a finding, in words. */
export const SOURCE_LABELS: Record<string, string> = {
  rule: 'rule',
  stat: 'statistics',
  ml: 'machine learning',
  ai: 'AI (Claude)',
}

/** Severity options for the shared checkbox dropdown (Investigations, Users, Logs). */
export function severityOptions(counts: Partial<Record<string, number>>, extra?: { value: string; label: string }) {
  return [
    ...PRIORITY_ORDER.map((p) => ({ value: p, label: PRIORITY_META[p].label, icon: PRIORITY_META[p].icon,
                                    iconClass: PRIORITY_META[p].iconClass, count: counts[p] })),
    ...(extra ? [{ ...extra, count: counts[extra.value] }] : []),
  ]
}

/** The severity a 0-100 risk falls in: the same cut-offs as the backend labels. */
export function priorityForRisk(risk: number): Priority {
  return risk >= 95 ? 'critical' : risk >= 75 ? 'high' : risk >= 45 ? 'medium' : 'low'
}
