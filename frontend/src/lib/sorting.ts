/** Shared table sorting (D111): ?sort=<key>&dir=asc in the URL. Same column again flips the
 *  direction; a new column starts highest first. Empty values always sort last. */
export type SortState<K extends string> = { sort: K | null; dir: 'asc' | 'desc' }

export function sortFrom<K extends string>(params: URLSearchParams, keys: readonly K[]): SortState<K> {
  const sort = params.get('sort')
  return { sort: (keys as readonly string[]).includes(sort ?? '') ? (sort as K) : null, dir: params.get('dir') === 'asc' ? 'asc' : 'desc' }
}

/** URL params after clicking a header (page reset to 1). `defaultKey` is written as no param. */
export function paramsForSort<K extends string>(params: URLSearchParams, current: SortState<K>, key: K, defaultKey?: K) {
  const next = new URLSearchParams(params)
  next.delete('page')
  const active = current.sort ?? defaultKey
  const dir = key === active && current.dir === 'desc' ? 'asc' : 'desc'
  if (key === defaultKey) next.delete('sort')
  else next.set('sort', key)
  if (dir === 'asc') next.set('dir', 'asc')
  else next.delete('dir')
  return next
}

/** Sort a copy by a numeric value; null values last in both directions, then by `tie`. */
export function sortRows<T>(rows: T[], value: (row: T) => number | null, dir: 'asc' | 'desc', tie: (a: T, b: T) => number) {
  const sign = dir === 'asc' ? 1 : -1
  return [...rows].sort((a, b) => {
    const va = value(a)
    const vb = value(b)
    if (va === null || vb === null) return va === vb ? tie(a, b) : va === null ? 1 : -1
    return sign * (va - vb) || tie(a, b)
  })
}
