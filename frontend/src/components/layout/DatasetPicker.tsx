import { Check, ChevronDown, Search } from 'lucide-react'
import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import type { Upload } from '@/api/uploads'
import { useDataset } from '@/lib/dataset'
import { matchUploads } from '@/lib/datasetSearch'
import { cn } from '@/lib/utils'

const when = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
const dateLabel = (u: Upload) => when.format(new Date(u.created_at))

/**
 * Which completed upload Logs shows: a searchable list instead of a native select, which
 * can't hold a search box. Type to filter (id, name, format, date), arrows to move, Enter to pick,
 * Escape to close. ARIA combobox + listbox, so screen readers announce the active option.
 */
export default function DatasetPicker() {
  const { uploadId, done, isPending } = useDataset()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const root = useRef<HTMLDivElement>(null)
  const listId = useId()

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent) => { if (!root.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  if (isPending) return <span className="text-sm text-muted-foreground">Loading uploads…</span>
  if (done.length === 0) return <span className="text-sm text-muted-foreground">No analyzed uploads yet</span>

  const current = done.find((u) => u.id === uploadId)
  const matches = matchUploads(done, query, dateLabel)
  const index = Math.min(active, Math.max(matches.length - 1, 0))

  function pick(u: Upload) {
    setOpen(false)
    setQuery('')
    // A different dataset starts a clean view of the same page (old filters may not apply).
    if (u.id !== uploadId) navigate(`${pathname}?upload=${u.id}`)
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(Math.min(index + 1, matches.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(Math.max(index - 1, 0)) }
    else if (e.key === 'Enter' && matches[index]) { e.preventDefault(); pick(matches[index]) }
    else if (e.key === 'Escape') setOpen(false)
  }

  return (
    <div ref={root} className="relative flex min-w-0 items-center gap-2 text-sm">
      <span className="label-caps shrink-0">Dataset</span>
      <button type="button" aria-haspopup="listbox" aria-expanded={open} onClick={() => { setOpen((v) => !v); setActive(0) }}
              className="inline-flex h-9 w-full min-w-0 items-center justify-between gap-2 rounded-lg border border-input bg-transparent px-3 text-left sm:w-[28rem] dark:bg-input/30">
        {/* User-supplied filename: plain text, escaped by React. */}
        <span className="truncate">
          {current ? `#${current.id} · ${current.filename} · ${dateLabel(current)}` : `Upload #${uploadId} is not available`}
        </span>
        <ChevronDown className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      </button>

      {open && (
        <div className="absolute top-full left-0 z-30 mt-1 w-full rounded-lg border bg-popover p-1 text-popover-foreground shadow-lg sm:left-[4.5rem] sm:w-[28rem]">
          <div className="relative p-1">
            <Search className="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              autoFocus role="combobox" aria-expanded aria-controls={listId} aria-label="Search datasets"
              aria-activedescendant={matches[index] ? `${listId}-${matches[index].id}` : undefined}
              value={query} onChange={(e) => { setQuery(e.target.value); setActive(0) }} onKeyDown={onKey}
              placeholder="Search by name, id, format or date…"
              className="h-9 w-full rounded-md border border-input bg-transparent pr-2 pl-8 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
          </div>
          <ul id={listId} role="listbox" aria-label="Datasets" className="max-h-80 overflow-y-auto py-1">
            {matches.length === 0 && <li className="px-3 py-2 text-muted-foreground">No datasets match.</li>}
            {matches.map((u, i) => (
              <li key={u.id} id={`${listId}-${u.id}`} role="option" aria-selected={u.id === uploadId}
                  onMouseEnter={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); pick(u) }}
                  className={cn('flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5', i === index && 'bg-accent')}>
                <Check className={cn('size-4 shrink-0', u.id === uploadId ? 'opacity-100' : 'opacity-0')} aria-hidden />
                <span className="tech text-muted-foreground">#{u.id}</span>
                <span className="min-w-0 flex-1 truncate">{u.filename}</span>
                <span className="meta shrink-0">
                  {u.line_count !== null ? `${u.line_count.toLocaleString()} lines · ` : ''}{dateLabel(u)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
