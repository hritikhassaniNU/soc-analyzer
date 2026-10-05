import { describe, expect, it } from 'vitest'
import type { Upload } from '@/api/uploads'
import { applyUploadFilters, uploadFiltersFrom } from '@/lib/uploadFilters'

const up = (id: number, filename: string, status: string, format: string) => ({ id, filename, status, format }) as Upload
const uploads = [up(1, 'zscaler_sample.csv', 'done', 'csv'), up(2, 'week3.txt', 'done', 'json'), up(3, 'junk.log', 'failed', 'csv')]

describe('upload filters', () => {
  it('reads the URL and ignores unknown values', () => {
    expect(uploadFiltersFrom(new URLSearchParams('q=%20week%20&status=done,bogus&format=json')))
      .toEqual({ q: 'week', statuses: ['done'], formats: ['json'] })
  })
  it('filters by name or id, status and format', () => {
    const none = { q: '', statuses: [], formats: [] }
    expect(applyUploadFilters(uploads, { ...none, q: 'SAMPLE' }).map((u) => u.id)).toEqual([1])
    expect(applyUploadFilters(uploads, { ...none, q: '#3' }).map((u) => u.id)).toEqual([3])
    expect(applyUploadFilters(uploads, { ...none, statuses: ['failed'] }).map((u) => u.id)).toEqual([3])
    expect(applyUploadFilters(uploads, { ...none, statuses: ['done'], formats: ['csv'] }).map((u) => u.id)).toEqual([1])
  })
})
