import { describe, expect, it } from 'vitest'
import { checkFile, EXTENSIONS_TEXT, formatLabel, MAX_UPLOAD_MB } from '@/lib/uploadRules'

// The file dialog's `accept` greys out other types, so this path can't be clicked through by hand.
describe('checkFile', () => {
  it.each(['proxy.log', 'notes.txt', 'export.csv', 'EXPORT.CSV'])('accepts %s', (name) => {
    expect(checkFile({ name, size: 1000 })).toBeNull()
  })

  it.each(['report.pdf', 'image.png', 'events.xml', 'archive.gz', 'archive.zip', 'csv'])('rejects %s', (name) => {
    expect(checkFile({ name, size: 1000 })).toMatch(/Unsupported file type/)
  })

  it('rejects files over the size limit and accepts exactly the limit', () => {
    const limit = MAX_UPLOAD_MB * 1024 * 1024
    expect(checkFile({ name: 'big.log', size: limit })).toBeNull()
    expect(checkFile({ name: 'big.log', size: limit + 1 })).toMatch(/larger than 1024 MB/)
  })
})

describe('formats', () => {
  it('accepts JSON-lines extensions', () => {
    for (const name of ['a.json', 'a.jsonl', 'a.ndjson']) expect(checkFile({ name, size: 10 })).toBeNull()
  })
  it('labels formats for display', () => {
    expect(formatLabel('json')).toBe('JSON lines')
    expect(formatLabel('csv')).toBe('CSV')
  })
})

describe('gzip', () => {
  it.each(['events.csv.gz', 'events.jsonl.GZ', 'proxy.log.gz'])('accepts %s', (name) => {
    expect(checkFile({ name, size: 10 })).toBeNull()
  })
})

describe('upload help text', () => {
  it('lists every accepted extension, including .log and .txt', () => {
    expect(EXTENSIONS_TEXT).toBe('.log, .txt, .csv, .json, .jsonl or .ndjson')
  })

  it('accepts .log and .txt, plain or gzipped', () => {
    for (const name of ['proxy.log', 'export.TXT', 'proxy.log.gz', 'export.txt.gz']) {
      expect(checkFile({ name, size: 1 })).toBeNull()
    }
  })
})
