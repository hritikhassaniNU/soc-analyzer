import { describe, expect, it } from 'vitest'
import { bucketLabel, capitalize, capitalizeEach, formatBytes, formatCompact, formatDateTime, formatPercent, formatRelative, formatUtc } from '@/lib/format'

describe('formatBytes', () => {
  it.each([
    [120, '120 B'], [4_694_494, '4.7 MB'], [512_000, '512 KB'], [2_500_000_000, '2.5 GB'],
  ])('%i -> %s', (bytes, text) => expect(formatBytes(bytes)).toBe(text))
})

describe('formatRelative', () => {
  const now = new Date('2026-10-03T12:00:00Z')
  it.each([
    ['2026-10-03T11:59:55Z', 'just now'],
    ['2026-10-03T11:55:00Z', '5 minutes ago'],
    ['2026-10-03T09:00:00Z', '3 hours ago'],
    ['2026-10-02T12:00:00Z', 'yesterday'],
  ])('%s -> %s', (iso, text) => expect(formatRelative(iso, now)).toBe(text))
})

describe('formatCompact / formatPercent', () => {
  it.each([[1284, '1,284'], [9999, '9,999'], [17441, '17.4K'], [4_200_000, '4.2M']])(
    '%i -> %s', (value, text) => expect(formatCompact(value)).toBe(text),
  )
  it.each([[0, '0%'], [0.0036, '0.4%'], [0.25, '25%']])('%f -> %s', (f, text) => expect(formatPercent(f)).toBe(text))
})

describe('formatDateTime', () => {
  it('always includes a time zone name', () => {
    expect(formatDateTime('2026-10-02T21:16:12Z')).toMatch(/[A-Z]{2,5}|GMT/)
  })
})

describe('formatUtc', () => {
  it('shows log times in UTC with a 24-hour clock, whatever the browser zone', () => {
    expect(formatUtc('2026-10-06T14:05:00Z')).toMatch(/14:05 UTC$/)
    expect(formatUtc('2026-09-21T07:33:03Z')).toMatch(/07:33 UTC$/)
  })
})

describe('capitalize', () => {
  it('uppercases only the first letter', () => {
    expect(capitalize('command & control')).toBe('Command & control')
    expect(capitalize('')).toBe('')
  })
})

describe('no comma between date and time', () => {
  it('joins date and time with a space', () => {
    expect(formatUtc('2026-09-29T08:29:00Z')).toMatch(/2026 08:29 UTC$/)
    expect(formatUtc('2026-09-29T08:29:00Z')).not.toMatch(/2026,/)
  })
})

describe('bucketLabel', () => {
  it('names every bucket size in words', () => {
    expect([1, 5, 15, 60, 360, 1440].map(bucketLabel)).toEqual(['minute', '5 minutes', '15 minutes', 'hour', '6 hours', 'day'])
  })
})

describe('capitalizeEach', () => {
  it('capitalizes every item of a category list', () => {
    expect(capitalizeEach('Command & control, suspicious domain (AI), unusual hours'))
      .toBe('Command & control, Suspicious domain (AI), Unusual hours')
    expect(capitalizeEach('large upload')).toBe('Large upload')
  })
})
