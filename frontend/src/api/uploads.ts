import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { FormatChoice } from '@/lib/uploadRules'
import { api, errorMessage, unwrap } from '@/api/client'
import type { components } from '@/api/schema'
import { HttpError } from '@/lib/queryClient'

export type Upload = components['schemas']['UploadOut']
export type UploadDetail = components['schemas']['UploadDetail']
export type UploadCreated = components['schemas']['UploadCreated']

export const uploadsQueryKey = ['uploads'] as const
export const uploadQueryKey = (id: number) => ['uploads', id] as const

const POLL_MS = 2000

export function isActive(status: string): boolean {
  return status === 'queued' || status === 'processing'
}

/** All uploads, newest first. Polls every 2 s only while something is queued/processing. */
export function useUploads() {
  return useQuery({
    queryKey: uploadsQueryKey,
    queryFn: () => unwrap(api.GET('/api/uploads')),
    refetchInterval: (query) => (query.state.data?.some((u) => isActive(u.status)) ? POLL_MS : false),
  })
}

/** One upload with parse results. Polls while it is queued/processing. */
export function useUpload(id: number) {
  return useQuery({
    queryKey: uploadQueryKey(id),
    queryFn: () => unwrap(api.GET('/api/uploads/{upload_id}', { params: { path: { upload_id: id } } })),
    refetchInterval: (query) => (query.state.data && isActive(query.state.data.status) ? POLL_MS : false),
  })
}

/**
 * POST the file with XMLHttpRequest: fetch() has no upload-progress events, and a 500 MB upload
 * needs a progress bar. Same-origin, so the session cookie is sent automatically.
 * Resolves to the created upload; rejects with HttpError like every other API call.
 */
export function uploadFile(
  file: File,
  logTimezone: string,
  format: FormatChoice,
  onProgress: (fraction: number) => void,
): Promise<UploadCreated> {
  return new Promise((resolve, reject) => {
    const form = new FormData()
    form.append('file', file)
    form.append('log_timezone', logTimezone)
    form.append('format', format)

    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/uploads')
    xhr.responseType = 'json'
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total)
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response as UploadCreated)
      } else {
        const detail = (xhr.response as { detail?: unknown } | null)?.detail
        reject(new HttpError(xhr.status, errorMessage(detail) ?? xhr.statusText))
      }
    }
    xhr.onerror = () => reject(new HttpError(0, "Can't reach the server"))
    xhr.send(form)
  })
}

export function useCreateUpload(onProgress: (fraction: number) => void) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ file, logTimezone, format }: { file: File; logTimezone: string; format: FormatChoice }) =>
      uploadFile(file, logTimezone, format, onProgress),
    onSuccess: (upload) => {
      // Show it at the top immediately; the refetch then starts polling its status.
      queryClient.setQueryData<Upload[]>(uploadsQueryKey, (old) => [upload, ...(old ?? [])])
      return queryClient.invalidateQueries({ queryKey: uploadsQueryKey })
    },
  })
}

export function useDeleteUpload() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) =>
      unwrap(api.DELETE('/api/uploads/{upload_id}', { params: { path: { upload_id: id } } })),
    onSuccess: (_data, id) => {
      queryClient.setQueryData<Upload[]>(uploadsQueryKey, (old) => old?.filter((u) => u.id !== id))
      queryClient.removeQueries({ queryKey: uploadQueryKey(id) })
      return queryClient.invalidateQueries({ queryKey: uploadsQueryKey })
    },
  })
}
