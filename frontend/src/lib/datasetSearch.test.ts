import { describe, expect, it } from 'vitest'
import type { Upload } from '@/api/uploads'
import { matchUploads } from '@/lib/datasetSearch'

const up = (id: number, filename: string, created: string) => ({ id, filename, format: 'csv', created_at: created }) as Upload
const uploads = [up(28, 'zscaler_week3.txt', 'Oct 4'), up(24, 'zscaler_sample.csv', 'Oct 3'), up(2, 'zscaler_clean.csv', 'Oct 2')]
const label = (u: Upload) => u.created_at

describe('matchUploads', () => {
  it('matches every word anywhere in id, name, format and date', () => {
    expect(matchUploads(uploads, 'sample oct 3', label).map((u) => u.id)).toEqual([24])
    expect(matchUploads(uploads, '#2', label).map((u) => u.id)).toEqual([28, 24, 2])
    expect(matchUploads(uploads, 'CLEAN', label).map((u) => u.id)).toEqual([2])
    expect(matchUploads(uploads, '  ', label)).toHaveLength(3)
    expect(matchUploads(uploads, 'nothing', label)).toEqual([])
  })
})
