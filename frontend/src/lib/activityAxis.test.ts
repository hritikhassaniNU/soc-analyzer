import { describe, expect, it } from 'vitest'
import { midnightTicks } from '@/lib/activityAxis'

const at = (iso: string) => Date.parse(iso)

describe('midnightTicks', () => {
  it('puts one tick per UTC midnight inside the range', () => {
    expect(midnightTicks(at('2026-10-05T07:00:00Z'), at('2026-10-07T20:00:00Z')))
      .toEqual([at('2026-10-06T00:00:00Z'), at('2026-10-07T00:00:00Z')])
  })
  it('thins long ranges to at most 8 ticks', () => {
    const ticks = midnightTicks(at('2026-09-21T00:00:00Z'), at('2026-10-11T23:00:00Z'))
    expect(ticks.length).toBeLessThanOrEqual(8)
    expect(ticks[0]).toBe(at('2026-09-21T00:00:00Z'))
  })
})
