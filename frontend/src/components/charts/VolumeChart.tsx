import { type ReactNode, useState } from 'react'
import { Bar, CartesianGrid, ComposedChart, Line, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { midnightTicks } from '@/lib/activityAxis'
import { bucketLabel, formatCompact } from '@/lib/format'
import { cn } from '@/lib/utils'
import ChartTooltip from '@/components/charts/ChartTooltip'

export type VolumeSeries = 'total' | 'blocked' | 'flagged'
export type VolumePoint = { ts: string; total: number; blocked: number; flagged: number }

const AXIS_TICK = { fill: 'var(--muted-foreground)', fontSize: 12 }
const full = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' })
const dayTick = new Intl.DateTimeFormat(undefined, { day: 'numeric', weekday: 'short', timeZone: 'UTC' })
const timeTick = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' })
const VOLUME_SERIES = [
  { key: 'total', label: 'All events', color: 'var(--series-1)' },
  { key: 'blocked', label: 'Blocked', color: 'var(--series-2)' },
  { key: 'flagged', label: 'Flagged by rules', color: 'var(--series-3)' },
] as const

/**
 * Events over time: all events as soft bars, Blocked and rule-flagged as lines (overlapping
 * counts, so lines, not stacks). Optional shaded windows (an incident) and click-to-select a bucket.
 * Legend + tooltip name every series; callers offer the numbers as a table where it matters.
 */
export default function VolumeChart({ points, bucketMinutes, height = 160, shade, onSelect, label, title, defaultHidden = [] }: {
  points: VolumePoint[]; bucketMinutes: number; height?: number; label: string; title?: ReactNode
  defaultHidden?: readonly VolumeSeries[] // series off until the legend turns them on
  shade?: { start: string; end: string; color: string; label: string }
  onSelect?: (start: string, end: string) => void
}) {
  const [hidden, setHidden] = useState<ReadonlySet<string>>(() => new Set(defaultHidden)) // legend toggles
  const data = points.map((p) => ({ ...p, t: Date.parse(p.ts) }))
  if (data.length === 0) return null
  const first = data[0].t
  const last = data[data.length - 1].t
  const multiDay = last - first > 86_400_000
  const step = bucketMinutes * 60_000
  const canZoom = !!onSelect && bucketMinutes > 1 // 1-minute bars are the finest the API gives
  // Shade edges snapped to bucket starts inside the data (category axis values).
  const snap = (t: number) => Math.min(last, Math.max(first, first + Math.floor((t - first) / step) * step))
  const zoomUnit = bucketLabel(bucketMinutes).replace(/^(\d+) (\w+?)s$/, '$1-$2 window') // "15-minute window"
  return (
    <div className="flex flex-col gap-2">
      {/* Title, legend and hint on one line; legend entries show/hide their series. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {title}
        {shade && (
          // The shaded band is named in the legend, never an unexplained color.
          <span className="inline-flex items-center gap-1.5 px-1">
            <span className="size-2.5 rounded-sm" style={{ background: shade.color, opacity: 0.35 }} aria-hidden /> {shade.label}
          </span>
        )}
        {VOLUME_SERIES.map((s) => (
          <button key={s.key} type="button" aria-pressed={!hidden.has(s.key)} title={hidden.has(s.key) ? `Show ${s.label}` : `Hide ${s.label}`}
                  onClick={() => setHidden((h) => { const n = new Set(h); if (n.has(s.key)) n.delete(s.key); else n.add(s.key); return n })}
                  className={cn('inline-flex items-center gap-1.5 rounded px-1 hover:text-foreground', hidden.has(s.key) && 'line-through opacity-50')}>
            <span className={s.key === 'total' ? 'size-2.5 rounded-sm opacity-40' : 'h-0.5 w-3 rounded'} style={{ background: s.color }} aria-hidden />
            {s.label}
          </button>
        ))}
      </div>
      <div style={{ height }} role="img" aria-label={label}>
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}
                         onClick={(e) => {
                           const t = Number((e as { activeLabel?: unknown } | null)?.activeLabel)
                           if (canZoom && Number.isFinite(t)) onSelect?.(new Date(t).toISOString(), new Date(t + step).toISOString())
                         }}
                         style={{ cursor: canZoom ? 'pointer' : undefined }}>
            <CartesianGrid vertical={false} stroke="var(--viz-grid)" />
            {shade && (
              <ReferenceArea x1={snap(Date.parse(shade.start))} x2={snap(Date.parse(shade.end))} fill={shade.color} fillOpacity={0.12} stroke="none" ifOverflow="hidden" />
            )}
            {/* Category axis: every bucket gets a real bar width, even when a zoom leaves a few. */}
            <XAxis dataKey="t" type="category" minTickGap={24} interval="preserveStartEnd"
                   ticks={multiDay ? midnightTicks(first, last) : undefined}
                   tickFormatter={(t) => (multiDay ? dayTick : timeTick).format(t)}
                   tick={AXIS_TICK} axisLine={{ stroke: 'var(--viz-axis)' }} tickLine={false} />
            <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} width={48} tickFormatter={(v) => formatCompact(Number(v))} />
            <Tooltip cursor={{ fill: 'var(--muted)', opacity: 0.4 }}
                     content={<ChartTooltip title={(t) => `${full.format(Number(t))} UTC`}
                                            names={(k) => VOLUME_SERIES.find((s) => s.key === k)?.label ?? k}
                                            hint={canZoom ? () => `Click to zoom to this ${zoomUnit}` : undefined} />} />
            <Bar dataKey="total" name="total" hide={hidden.has('total')} fill="var(--series-1)" fillOpacity={0.35} isAnimationActive={false} radius={[2, 2, 0, 0]} />
            <Line dataKey="blocked" name="blocked" hide={hidden.has('blocked')} stroke="var(--series-2)" strokeWidth={2} dot={false} isAnimationActive={false} />
            <Line dataKey="flagged" name="flagged" hide={hidden.has('flagged')} stroke="var(--series-3)" strokeWidth={2} dot={false} isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
