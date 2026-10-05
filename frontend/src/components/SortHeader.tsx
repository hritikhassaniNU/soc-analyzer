import { ArrowDown, ArrowUp } from 'lucide-react'
import { TableHead } from '@/components/ui/table'
import { cn } from '@/lib/utils'

/** A sortable column header, the same on every table (D111): click to sort highest first, click
 *  again to flip; the arrow and aria-sort show the order. */
export default function SortHeader({ label, active, dir, onSort, align, className }: {
  label: string; active: boolean; dir: 'asc' | 'desc'; onSort: () => void; align?: 'right'; className?: string
}) {
  const Arrow = active && dir === 'asc' ? ArrowUp : ArrowDown
  return (
    <TableHead aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}
               className={cn(align === 'right' && 'text-right', className)}>
      <button type="button" onClick={onSort} title={active ? 'Click to reverse the order' : 'Sort by this column'}
              className={cn('inline-flex items-center gap-1 hover:text-foreground', active && 'text-foreground')}>
        {label}
        <Arrow className={cn('size-3.5', active ? 'opacity-100' : 'opacity-30')} aria-hidden />
      </button>
    </TableHead>
  )
}
