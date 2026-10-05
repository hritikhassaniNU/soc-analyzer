import { describe, expect, it } from 'vitest'
import type { Upload } from '@/api/uploads'
import { defaultDataset, uploadFromParams } from '@/lib/dataset'

const done = [{ id: 21 }, { id: 19 }, { id: 15 }] as Upload[] // newest first, like the API

describe('dataset selection', () => {
  it('reads a valid ?upload= and ignores junk', () => {
    expect(uploadFromParams(new URLSearchParams('upload=21'))).toBe(21)
    for (const bad of ['', 'upload=abc', 'upload=-3', 'upload=1.5']) {
      expect(uploadFromParams(new URLSearchParams(bad))).toBeNull()
    }
  })
  it('defaults to the remembered upload while it is still available, else the newest', () => {
    expect(defaultDataset(done, 19)).toBe(19)
    expect(defaultDataset(done, 7)).toBe(21) // remembered one was deleted
    expect(defaultDataset(done, null)).toBe(21)
    expect(defaultDataset([], null)).toBeNull()
  })
})
