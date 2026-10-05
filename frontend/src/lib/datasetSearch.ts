import type { Upload } from '@/api/uploads'

/** Uploads matching a dataset-picker search: every word must appear in "#id filename format date"
 *  (case-insensitive), so "sample oct 3" or "#24" both work. */
export function matchUploads(uploads: Upload[], query: string, dateLabel: (u: Upload) => string): Upload[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) return uploads
  return uploads.filter((u) => {
    const text = `#${u.id} ${u.filename} ${u.format} ${dateLabel(u)}`.toLowerCase()
    return words.every((w) => text.includes(w))
  })
}
