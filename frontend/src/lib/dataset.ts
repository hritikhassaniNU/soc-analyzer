import { useEffect } from 'react'
import { useSearchParams } from 'react-router'
import { type Upload, useUploads } from '@/api/uploads'

// Which upload the Logs page shows (Dashboard and Investigations are company-wide). It lives in the URL (?upload=21),
// so a view can be bookmarked and shared and Back works. Without one, the last upload this
// browser picked is used, else the newest completed upload.

const STORAGE_KEY = 'soc.dataset'

function readRemembered(): number | null {
  try {
    const value = Number(localStorage.getItem(STORAGE_KEY))
    return Number.isInteger(value) && value > 0 ? value : null
  } catch {
    return null // storage can be unavailable (private mode, blocked site data)
  }
}

function remember(id: number): void {
  try {
    localStorage.setItem(STORAGE_KEY, String(id))
  } catch {
    // a convenience only: ignore
  }
}

/** The upload id in ?upload=, if it is a positive integer. */
export function uploadFromParams(params: URLSearchParams): number | null {
  const value = Number(params.get('upload'))
  return Number.isInteger(value) && value > 0 ? value : null
}

/** Default when the URL has none: the remembered one if it's still a completed upload, else the newest. */
export function defaultDataset(done: Upload[], remembered: number | null): number | null {
  if (remembered !== null && done.some((u) => u.id === remembered)) return remembered
  return done[0]?.id ?? null // the API lists newest first
}

export function useDataset() {
  const [params, setParams] = useSearchParams()
  const uploads = useUploads()
  const done = (uploads.data ?? []).filter((u) => u.status === 'done')
  const fromUrl = uploadFromParams(params)
  const fallback = uploads.data ? defaultDataset(done, readRemembered()) : null
  const uploadId = fromUrl ?? fallback

  // Put the default into the URL (replace: no extra Back step) so the view is shareable.
  useEffect(() => {
    if (fromUrl === null && fallback !== null) {
      setParams((current) => {
        const next = new URLSearchParams(current)
        next.set('upload', String(fallback))
        return next
      }, { replace: true })
    }
  }, [fromUrl, fallback, setParams])

  useEffect(() => {
    if (fromUrl !== null) remember(fromUrl)
  }, [fromUrl])

  return {
    uploadId,
    selected: done.find((u) => u.id === uploadId) ?? null, // null: deleted, failed or not finished
    done,
    isPending: uploads.isPending,
    isError: uploads.isError,
  }
}
