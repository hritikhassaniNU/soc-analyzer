import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { pageWindow } from '@/lib/pagination'

/** "Showing 51–75 of 17,546" + Previous · 1 … 4 5 6 … 702 · Next. Shared by Users and Logs. */
export default function Pagination({ page, pages, from, to, total, noun, onPage, busy = false }: {
  page: number; pages: number; from: number; to: number; total: number | null; noun: string
  onPage: (page: number) => void; busy?: boolean
}) {
  return (
    <nav aria-label="Pages" className="flex flex-wrap items-center justify-between gap-2">
      <span className="meta">
        Showing {from.toLocaleString()}–{to.toLocaleString()}{total !== null && ` of ${total.toLocaleString()}`} {noun}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="sm" disabled={page <= 1 || busy} onClick={() => onPage(page - 1)}>
          <ChevronLeft /> Previous
        </Button>
        {pageWindow(page, pages).map((n, i) => n === 'gap' ? (
          <span key={`gap-${i}`} className="px-1 text-muted-foreground" aria-hidden>…</span>
        ) : (
          <Button key={n} variant={n === page ? 'default' : 'ghost'} size="sm" className="min-w-8 tabular-nums"
                  aria-current={n === page ? 'page' : undefined} aria-label={`Page ${n}`} disabled={busy && n !== page}
                  onClick={() => onPage(n)}>
            {n.toLocaleString()}
          </Button>
        ))}
        <Button variant="outline" size="sm" disabled={page >= pages || busy} onClick={() => onPage(page + 1)}>
          Next <ChevronRight />
        </Button>
      </div>
    </nav>
  )
}
