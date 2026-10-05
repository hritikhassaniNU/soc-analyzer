import { Check, ChevronDown, type LucideIcon } from 'lucide-react'
import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'

export type MultiOption = { value: string; label: string; icon?: LucideIcon; iconClass?: string; count?: number }

/**
 * A dropdown with checkboxes (D88): the same severity filter on Investigations, Users and Logs.
 * Nothing checked = all. The button says what's chosen ("Critical, High", "3 selected").
 * Native checkboxes inside, so keyboard and screen readers work; Escape or a click outside closes it.
 * The panel is rendered in a portal with fixed positioning (D101): cards use overflow-hidden, which
 * clipped it to one row when the list below was empty.
 */
export default function MultiSelect({ allLabel, label, options, selected, onChange }: {
  allLabel: string; label: string; options: MultiOption[]; selected: string[]; onChange: (values: string[]) => void
}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  const panelId = useId()
  const [pos, setPos] = useState<{ top?: number; bottom?: number; left: number; maxHeight: number } | null>(null)

  // Place the panel under the button (viewport coordinates), and follow it on scroll/resize.
  useLayoutEffect(() => {
    if (!open) return
    const place = () => {
      const r = root.current?.getBoundingClientRect()
      if (!r) return
      // Fit the viewport (the page can't scroll a fixed panel into view): open below when there's
      // room, otherwise above if that side has more space; cap the height and scroll inside.
      const margin = 8
      const below = window.innerHeight - r.bottom - margin
      const above = r.top - margin
      const wanted = Math.min(panel.current?.scrollHeight ?? 320, 420)
      const left = Math.max(margin, Math.min(r.left, window.innerWidth - 248))
      if (below >= wanted || below >= above) setPos({ top: r.bottom + 4, left, maxHeight: Math.max(below - 4, 120) })
      else setPos({ bottom: window.innerHeight - r.top + 4, left, maxHeight: Math.max(above - 4, 120) })
    }
    place()
    window.addEventListener('scroll', place, true)
    window.addEventListener('resize', place)
    return () => {
      window.removeEventListener('scroll', place, true)
      window.removeEventListener('resize', place)
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      const inside = root.current?.contains(e.target as Node) || panel.current?.contains(e.target as Node)
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !inside) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open])

  const chosen = options.filter((o) => selected.includes(o.value))
  const summary = chosen.length === 0 ? allLabel : chosen.length <= 2 ? chosen.map((o) => o.label).join(', ') : `${chosen.length} selected`
  const toggle = (value: string) =>
    onChange(selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value])

  return (
    <div ref={root} className="relative">
      <button type="button" aria-haspopup="true" aria-expanded={open} aria-controls={panelId} aria-label={`${label}: ${summary}`}
              onClick={() => setOpen((v) => !v)}
              className={cn('inline-flex h-9 items-center gap-2 rounded-lg border border-input bg-transparent px-3 text-sm dark:bg-input/30',
                chosen.length > 0 && 'border-primary')}>
        {summary}
        <ChevronDown className="size-4 text-muted-foreground" aria-hidden />
      </button>
      {open && pos && createPortal(
        <div ref={panel} id={panelId} role="group" aria-label={label}
             style={{ top: pos.top, bottom: pos.bottom, left: pos.left, maxHeight: pos.maxHeight }}
             className="fixed z-50 w-60 overflow-y-auto rounded-lg border bg-popover p-1 text-popover-foreground shadow-lg">
          {options.map((o) => {
            const on = selected.includes(o.value)
            return (
              <label key={o.value} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent">
                <input type="checkbox" className="peer sr-only" checked={on} onChange={() => toggle(o.value)} />
                <span aria-hidden className={cn('flex size-4 items-center justify-center rounded border peer-focus-visible:ring-2 peer-focus-visible:ring-ring',
                  on ? 'border-primary bg-primary text-primary-foreground' : 'border-input')}>
                  {on && <Check className="size-3" />}
                </span>
                {o.icon && <o.icon className={cn('size-4', o.iconClass)} aria-hidden />}
                <span className="flex-1">{o.label}</span>
                {o.count !== undefined && <span className="tabular-nums text-muted-foreground">{o.count.toLocaleString()}</span>}
              </label>
            )
          })}
          <div className="mt-1 flex justify-between border-t px-2 pt-1.5 pb-0.5">
            <button type="button" className="text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
                    disabled={selected.length === 0} onClick={() => onChange([])}>Clear</button>
            <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => setOpen(false)}>Done</button>
          </div>
        </div>,
        document.body,
      )}
    </div>
  )
}
