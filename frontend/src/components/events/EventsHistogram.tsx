import { type EventFilters, useEventHistogram } from '@/api/events'
import VolumeChart from '@/components/charts/VolumeChart'
import { bucketLabel } from '@/lib/format'
import { cn } from '@/lib/utils'

/** The Logs histogram (D118), like Splunk/Elastic: events over time for the CURRENT filters;
 *  clicking a bar narrows the time range to that bucket. */
export default function EventsHistogram({ uploadId, filters, onZoom }: {
  uploadId: number; filters: EventFilters; onZoom: (start: string, end: string) => void
}) {
  const histogram = useEventHistogram(uploadId, filters)
  const h = histogram.data
  if (!h || h.points.length === 0) return null
  const per = bucketLabel(h.bucket_minutes)
  return (
    <section className={cn('rounded-xl border bg-card p-4 transition-opacity', histogram.isPlaceholderData && 'opacity-60')}>
      {/* All events starts hidden (D129): its bars dwarf the Blocked and Flagged lines. */}
      <VolumeChart points={h.points} bucketMinutes={h.bucket_minutes} onSelect={onZoom} defaultHidden={['total']}
                   title={<h2 className="label-caps mr-2">Events per {per} (UTC)</h2>}
                   label={`Events per ${per} for the current filters`} />
    </section>
  )
}
