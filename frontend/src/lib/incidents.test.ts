import { describe, expect, it } from 'vitest'
import { formatTime, formatWindow, kindLabel, PRIORITY_META, PRIORITY_ORDER } from '@/lib/incidents'

describe('formatWindow (UTC)', () => {
  it('shows one day once', () => {
    expect(formatWindow('2026-09-22T14:05:00Z', '2026-09-22T22:05:03Z')).toMatch(/22.*14:05–22:05$/)
  })
  it('shows a single moment as one time', () => {
    expect(formatWindow('2026-09-23T10:15:00Z', '2026-09-23T10:15:40Z')).toMatch(/23.*10:15$/)
  })
  it('shows both days when the window crosses midnight', () => {
    const text = formatWindow('2026-09-24T13:17:10Z', '2026-09-25T13:04:00Z')
    expect(text).toMatch(/24.*13:17 – .*25.*13:04$/)
  })
  it('is UTC regardless of the browser zone', () => {
    expect(formatTime('2026-09-27T02:40:00Z')).toBe('02:40')
  })
})

describe('labels', () => {
  it('every priority has a word and an icon (never color alone)', () => {
    for (const p of PRIORITY_ORDER) {
      expect(PRIORITY_META[p].label).toBeTruthy()
      expect(PRIORITY_META[p].icon).toBeTruthy()
    }
  })
  it('names rule and statistical kinds, and falls back to the raw kind', () => {
    expect(kindLabel('zscaler_threat')).toBe('Zscaler threat')
    expect(kindLabel('off_hours')).toBe('Unusual hours')
    expect(kindLabel('behavioral_outlier')).toBe('Unusual combination (ML)')
    expect(kindLabel('something_new')).toBe('something_new')
  })
})
