import { describe, expect, it } from 'vitest'
import { pageWindow } from '@/lib/pagination'

describe('pageWindow', () => {
  it('shows first, last and the neighbors of the current page', () => {
    expect(pageWindow(5, 702)).toEqual([1, 'gap', 4, 5, 6, 'gap', 702])
    expect(pageWindow(1, 702)).toEqual([1, 2, 'gap', 702])
    expect(pageWindow(702, 702)).toEqual([1, 'gap', 701, 702])
  })
  it('fills a one-page gap instead of showing "…" and handles tiny totals', () => {
    expect(pageWindow(4, 6)).toEqual([1, 2, 3, 4, 5, 6])
    expect(pageWindow(1, 1)).toEqual([1])
    expect(pageWindow(2, 2)).toEqual([1, 2])
  })
})
