/** Page buttons to show: first, last, and the current page with one neighbor each side; gaps
 *  between them become "…". 1-based. e.g. (5, 702) -> [1, 'gap', 4, 5, 6, 'gap', 702]. */
export function pageWindow(page: number, pages: number): (number | 'gap')[] {
  const wanted = [...new Set([1, page - 1, page, page + 1, pages])].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b)
  const out: (number | 'gap')[] = []
  for (const n of wanted) {
    const prev = out[out.length - 1]
    if (typeof prev === 'number' && n - prev === 2) out.push(prev + 1) // a gap of one page: show it
    else if (typeof prev === 'number' && n - prev > 2) out.push('gap')
    out.push(n)
  }
  return out
}

export const PAGE_SIZE = 25

/** One page of an already filtered + sorted list. `page` is 1-based and clamped into range
 *  (a hand-edited ?page=99 shows the last page, not an empty table). */
export function paginate<T>(items: T[], page: number, size = PAGE_SIZE) {
  const pages = Math.max(1, Math.ceil(items.length / size))
  const current = Math.min(Math.max(1, Number.isInteger(page) ? page : 1), pages)
  const start = (current - 1) * size
  return { items: items.slice(start, start + size), page: current, pages, from: items.length ? start + 1 : 0,
           to: Math.min(start + size, items.length), total: items.length }
}
