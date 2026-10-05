type Entry = { name?: string | number; dataKey?: unknown; value?: unknown; color?: string; payload?: unknown }

/** One tooltip for every chart: the bucket, a row per series with its color key, and an
 *  optional muted last line saying what a click does, so the charts carry no instruction text. */
export default function ChartTooltip({ active, payload, label, title, names, hideZero, reverse, hint }: {
  active?: boolean; payload?: readonly Entry[]; label?: unknown
  title: (label: unknown) => string
  names: (key: string) => string
  hideZero?: boolean
  reverse?: boolean // stacked bars drawn bottom-up: list top segment first
  hint?: (label: unknown) => string | null
}) {
  if (!active || !payload?.length) return null
  const rows = (reverse ? [...payload].reverse() : payload).filter((p) => !hideZero || Number(p.value) > 0)
  const action = hint?.(label)
  return (
    <div className="rounded-lg border bg-popover px-3 py-2 text-[13px] shadow-md">
      <p className="font-medium text-foreground">{title(label)}</p>
      <ul className="mt-1 flex flex-col gap-0.5">
        {rows.map((p) => (
          <li key={String(p.dataKey)} className="flex items-center gap-2 text-muted-foreground">
            <span className="size-2 rounded-sm" style={{ background: p.color }} aria-hidden />
            <span className="flex-1">{names(String(p.dataKey))}</span>
            <span className="tabular-nums text-foreground">{Number(p.value).toLocaleString()}</span>
          </li>
        ))}
      </ul>
      {action && <p className="mt-1.5 border-t pt-1.5 text-xs text-muted-foreground">{action}</p>}
    </div>
  )
}
