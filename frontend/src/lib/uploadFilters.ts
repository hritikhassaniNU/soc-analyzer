import type { Upload } from '@/api/uploads'

/** Upload Logs filters (D100): ?q=sample&status=done,failed&format=csv. Unknown values are ignored. */
export const UPLOAD_STATUSES = { queued: 'Queued', processing: 'Processing', done: 'Scanned', failed: 'Failed' } as const
export const UPLOAD_FORMATS = { csv: 'CSV', json: 'JSON lines' } as const
export type UploadFilters = { q: string; statuses: string[]; formats: string[] }

const list = (raw: string | null, allowed: object) => (raw ?? '').split(',').filter((v) => v in allowed)

export function uploadFiltersFrom(params: URLSearchParams): UploadFilters {
  return {
    q: params.get('q')?.trim() ?? '',
    statuses: list(params.get('status'), UPLOAD_STATUSES),
    formats: list(params.get('format'), UPLOAD_FORMATS),
  }
}

export function applyUploadFilters(uploads: Upload[], f: UploadFilters): Upload[] {
  const needle = f.q.toLowerCase()
  return uploads.filter((u) =>
    (!needle || u.filename.toLowerCase().includes(needle) || `#${u.id}`.includes(needle))
    && (f.statuses.length === 0 || f.statuses.includes(u.status))
    && (f.formats.length === 0 || f.formats.includes(u.format)))
}
