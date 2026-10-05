/** "4.7 MB", "512 KB", "120 B" (decimal units, like file managers show). */
export function formatBytes(bytes: number): string {
  if (bytes < 1000) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = -1
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000
    unit += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

/** "just now", "5 minutes ago", "yesterday" (browser's built-in Intl, no date library). */
export function formatRelative(iso: string, now: Date = new Date()): string {
  const seconds = Math.round((new Date(iso).getTime() - now.getTime()) / 1000)
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60], ['minute', 60], ['hour', 24], ['day', 7], ['week', 4.35], ['month', 12], ['year', Infinity],
  ]
  let value = seconds
  for (const [unit, size] of steps) {
    if (Math.abs(value) < size) {
      return unit === 'second' && Math.abs(value) < 10 ? 'just now' : relative.format(Math.trunc(value), unit)
    }
    value /= size
  }
  return relative.format(Math.trunc(value), 'year')
}

const compact = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 })

/** 1,284 stays exact; 12,900 -> "12.9K"; 4,200,000 -> "4.2M" (stat tiles). */
export function formatCompact(value: number): string {
  return value < 10_000 ? value.toLocaleString() : compact.format(value)
}

/** 0.0036 -> "0.4%", 0 -> "0%". */
export function formatPercent(fraction: number): string {
  if (fraction === 0) return '0%'
  return `${(fraction * 100).toFixed(fraction < 0.1 ? 1 : 0)}%`
}

// Date and time formatted separately and joined with a space: no comma between them (D119).
const localDate = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
const localTime = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' })

/** "Oct 2, 2026 9:16 PM PDT": local time with its zone. For app actions (uploads, notes, edits). */
export function formatDateTime(iso: string): string {
  const d = new Date(iso)
  return `${localDate.format(d)} ${localTime.format(d)}`
}

const utcDate = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' })
const utcTime = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' })

/** "Oct 6, 2026 14:05 UTC": times FROM THE LOGS, always UTC like the events table and charts (D93). */
export function formatUtc(iso: string): string {
  const d = new Date(iso)
  return `${utcDate.format(d)} ${utcTime.format(d)} UTC`
}

/** "command & control" -> "Command & control" (CSS ::first-letter does nothing on inline elements). */
export function capitalize(text: string): string {
  return text ? text[0].toUpperCase() + text.slice(1) : text
}

/** A chart bucket in words: 1 -> "minute", 15 -> "15 minutes", 60 -> "hour", 360 -> "6 hours",
 *  1440 -> "day" (D125; never "0.0166 hours"). */
export function bucketLabel(minutes: number): string {
  if (minutes % 1440 === 0) return minutes === 1440 ? 'day' : `${minutes / 1440} days`
  if (minutes % 60 === 0) return minutes === 60 ? 'hour' : `${minutes / 60} hours`
  return minutes === 1 ? 'minute' : `${minutes} minutes`
}
