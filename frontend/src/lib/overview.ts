/** "↑ 18.4% vs previous 7 days": the change between two periods of event counts. Neutral wording:
 *  more or less traffic is neither good nor bad. null previous = nothing to compare with. */
export function trendText(last: number, previous: number | null, days: number): string {
  if (previous === null) return `No previous ${days} days to compare`
  if (previous === 0) return last === 0 ? `No events in either ${days}-day period` : `New activity vs previous ${days} days`
  const change = (last - previous) / previous
  if (Math.abs(change) < 0.0005) return `No change vs previous ${days} days`
  return `${change > 0 ? '↑' : '↓'} ${Math.abs(change * 100).toFixed(1)}% vs previous ${days} days`
}

/** Status filter values for the investigations queue: "unresolved" = open + investigating. */
export const STATUS_FILTERS = {
  unresolved: 'Unresolved',
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
} as const
