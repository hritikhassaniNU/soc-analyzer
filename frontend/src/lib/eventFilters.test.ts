import { describe, expect, it } from 'vitest'
import { caseSearchParams, drillDownParams, filtersFromParams, inputFromUtc, paramsWithFilters, timePresets, utcFromInput } from '@/lib/eventFilters'

describe('filtersFromParams', () => {
  it('reads every supported filter', () => {
    const params = new URLSearchParams(
      'tab=events&username=jdoe&action=Blocked&category=File%20Sharing&host=mega.nz&flagged=1' +
        '&rule=zscaler_threat&start=2026-09-27T02:40:00Z&end=2026-09-27T03:10:00Z',
    )
    expect(filtersFromParams(params)).toEqual({
      username: 'jdoe', action: 'Blocked', category: 'File Sharing', host: 'mega.nz', flagged: true,
      source: ['rule:zscaler_threat'], start: '2026-09-27T02:40:00Z', end: '2026-09-27T03:10:00Z',
    })
  })

  it('ignores malformed values from a hand-edited URL', () => {
    const params = new URLSearchParams('action=Maybe&rule=drop_tables&start=yesterday&flagged=yes&username=%20%20')
    expect(filtersFromParams(params)).toEqual({})
  })
})

describe('paramsWithFilters', () => {
  it('round-trips and keeps unrelated params like the tab', () => {
    const filters = { username: 'jdoe', flagged: true, start: '2026-09-27T02:40:00Z' }
    const params = paramsWithFilters(new URLSearchParams('tab=events&action=Blocked'), filters)

    expect(params.get('tab')).toBe('events')
    expect(params.get('action')).toBeNull() // old filters are replaced, not merged
    expect(filtersFromParams(params)).toEqual(filters)
  })
})

describe('UTC datetime-local helpers', () => {
  it('treats the input as UTC both ways', () => {
    expect(utcFromInput('2026-09-24T11:00')).toBe('2026-09-24T11:00:00Z')
    expect(inputFromUtc('2026-09-24T11:00:00Z')).toBe('2026-09-24T11:00')
    expect(utcFromInput('')).toBeUndefined()
  })
})

describe('drillDownParams', () => {
  it('opens Logs for the upload and user, rounding the window outward to whole minutes', () => {
    const params = drillDownParams(21, 'jdoe', '2026-09-22T14:05:00+00:00', '2026-09-22T22:05:03+00:00')

    expect(params.get('upload')).toBe('21')
    expect(filtersFromParams(params)).toEqual({
      username: 'jdoe', start: '2026-09-22T14:05:00Z', end: '2026-09-22T22:06:00Z',
    })
  })

  it('includes an event exactly on a whole minute (the end filter is exclusive)', () => {
    const params = drillDownParams(21, 'amiller', '2026-09-23T10:15:00Z', '2026-09-23T10:16:00Z')

    expect(params.get('end')).toBe('2026-09-23T10:17:00Z')
  })

  it('round-trips finding-window sources (the old in_window=1 means both window types)', () => {
    const next = paramsWithFilters(new URLSearchParams(), { source: ['window:stat', 'window:ml'] })

    expect(next.get('sources')).toBe('window:stat,window:ml')
    expect(filtersFromParams(next)).toEqual({ source: ['window:stat', 'window:ml'] })
  })
})

describe('filter bar parameters (D83)', () => {
  it('round-trips search, severity, source and anomaly only', () => {
    const params = new URLSearchParams('q=jdoe&severity=critical&window=stat&anomalous=1')
    const filters = filtersFromParams(params)
    // ?severity= is ignored on Logs (D95); the old ?window= becomes a checked source (D99).
    expect(filters).toEqual({ q: 'jdoe', source: ['window:stat'], anomalous: true })
    expect(paramsWithFilters(new URLSearchParams(), filters).toString()).toBe('q=jdoe&sources=window%3Astat&anomalous=1')
  })

  it('ignores unknown severities and sources', () => {
    expect(filtersFromParams(new URLSearchParams('severity=extreme&window=rules'))).toEqual({})
  })

  it('counts presets back from now, end exclusive (D112)', () => {
    const p = timePresets(Date.parse('2026-09-27T21:59:30Z'))
    expect(p.last_24h).toMatchObject({ label: 'Last 24 hours', start: '2026-09-26T22:00:00Z', end: '2026-09-27T22:00:00Z' })
    expect(p.last_3d).toMatchObject({ start: '2026-09-24T22:00:00Z', end: '2026-09-27T22:00:00Z' })
    expect(p.last_7d).toMatchObject({ start: '2026-09-20T22:00:00Z', end: '2026-09-27T22:00:00Z' })
  })
})

describe('sources (D99)', () => {
  it('reads the checkbox list and folds old ?rule / ?in_window links into it', () => {
    expect(filtersFromParams(new URLSearchParams('sources=window:ml,rule:scripted_client,bogus')).source)
      .toEqual(['rule:scripted_client', 'window:ml'])
    expect(filtersFromParams(new URLSearchParams('in_window=1')).source).toEqual(['window:stat', 'window:ml'])
  })
})

describe('caseSearchParams', () => {
  it('turns a case search into Logs URL filters with "Z" times', () => {
    const params = caseSearchParams(7, {
      username: 'jdoe', host: 'mega.nz', action: null, anomalous: true,
      start: '2026-09-27T02:40:00+00:00', end: '2026-09-27T03:09:00+00:00',
    })
    expect(params.toString()).toBe(
      'upload=7&username=jdoe&host=mega.nz&start=2026-09-27T02%3A40%3A00Z&end=2026-09-27T03%3A09%3A00Z&anomalous=1')
  })

  it('leaves out filters a search does not set (blast radius: host only)', () => {
    const params = caseSearchParams(7, { username: null, host: 'mega.nz', action: null, anomalous: false, start: null, end: null })
    expect(params.toString()).toBe('upload=7&host=mega.nz')
  })
})
