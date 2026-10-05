import { describe, expect, it } from 'vitest'
import { paramsForSort, sortFrom, sortRows } from '@/lib/sorting'

describe('shared sorting', () => {
  const keys = ['risk', 'alerts'] as const
  it('reads the URL and flips on the same column, resets on a new one', () => {
    const s = sortFrom(new URLSearchParams('sort=alerts&dir=asc&page=3'), keys)
    expect(s).toEqual({ sort: 'alerts', dir: 'asc' })
    expect(paramsForSort(new URLSearchParams('sort=alerts&page=3'), { sort: 'alerts', dir: 'desc' }, 'alerts').toString())
      .toBe('sort=alerts&dir=asc')
    expect(paramsForSort(new URLSearchParams('sort=alerts&dir=asc'), { sort: 'alerts', dir: 'asc' }, 'risk', 'risk').toString()).toBe('')
  })
  it('sorts with empty values last in both directions', () => {
    const rows = [{ n: 2 }, { n: null }, { n: 5 }] as { n: number | null }[]
    const tie = () => 0
    expect(sortRows(rows, (r) => r.n, 'desc', tie).map((r) => r.n)).toEqual([5, 2, null])
    expect(sortRows(rows, (r) => r.n, 'asc', tie).map((r) => r.n)).toEqual([2, 5, null])
  })
})
