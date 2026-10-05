import { describe, expect, it } from 'vitest'
import { splitEntities } from '@/lib/richText'

describe('splitEntities', () => {
  it('finds known users (whole words) and domains, keeps everything else as text', () => {
    const parts = splitEntities("jdoe's laptop beaconed to cdn-update-check.xyz; jdoex is not a user.", ['jdoe'])
    expect(parts).toEqual([
      { kind: 'user', value: 'jdoe' },
      { kind: 'text', value: "'s laptop beaconed to " },
      { kind: 'domain', value: 'cdn-update-check.xyz' },
      { kind: 'text', value: '; jdoex is not a user.' },
    ])
  })

  it('does not treat numbers, times or sentence ends as domains', () => {
    const parts = splitEntities('102,458 events at 14:05. Done. 3.5 MB to mega.nz.', [])
    expect(parts.filter((p) => p.kind === 'domain').map((p) => p.value)).toEqual(['mega.nz'])
  })

  it('never builds markup: injected tags stay plain text', () => {
    const parts = splitEntities('<img src=x onerror=alert(1)> via evil.example.com', [])
    expect(parts[0]).toEqual({ kind: 'text', value: '<img src=x onerror=alert(1)> via ' })
    expect(parts[1]).toEqual({ kind: 'domain', value: 'evil.example.com' })
  })
})

describe('threat names are not domains', () => {
  it('keeps Trojan.GenericKD.71345 as text', () => {
    const parts = splitEntities('blocked Trojan.GenericKD.71345 from files.anonshare.io', [])
    expect(parts.filter((p) => p.kind === 'domain').map((p) => p.value)).toEqual(['files.anonshare.io'])
  })
})
