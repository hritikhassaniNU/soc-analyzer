import { describe, expect, it } from 'vitest'
import { trendText } from '@/lib/overview'

describe('trendText', () => {
  it('shows the change with one decimal and a direction arrow', () => {
    expect(trendText(1184, 1000, 7)).toBe('↑ 18.4% vs previous 7 days')
    expect(trendText(900, 1000, 7)).toBe('↓ 10.0% vs previous 7 days')
    expect(trendText(1000, 1000, 7)).toBe('No change vs previous 7 days')
  })
  it('says so when there is nothing to compare with', () => {
    expect(trendText(500, null, 7)).toBe('No previous 7 days to compare')
    expect(trendText(500, 0, 7)).toBe('New activity vs previous 7 days')
  })
})
