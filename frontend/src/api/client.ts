import createClient from 'openapi-fetch'
import { HttpError } from '@/lib/queryClient'
import type { paths } from './schema'

/**
 * Typed API client. Paths, params and response shapes come from the backend's
 * OpenAPI schema (`npm run gen:api`), so a backend change that breaks the
 * frontend becomes a compile error instead of a runtime bug.
 *
 * baseUrl '' = same origin (Vite proxy in dev, FastAPI serving the UI in prod),
 * so the httpOnly session cookie is sent automatically.
 */
export const api = createClient<paths>({ baseUrl: '' })

type ApiResult<T> = { data?: T; error?: unknown; response: Response }

/**
 * openapi-fetch RETURNS errors ({ data, error, response }) instead of throwing.
 * TanStack Query needs a THROWN error to enter its error state, so we convert here.
 */
export async function unwrap<T>(request: Promise<ApiResult<T>>): Promise<T> {
  const { data, error, response } = await request
  if (!response.ok) {
    const detail = typeof error === 'object' && error !== null && 'detail' in error ? error.detail : undefined
    throw new HttpError(response.status, errorMessage(detail) ?? response.statusText)
  }
  return data as T
}

/**
 * FastAPI errors: our own are `{"detail": "message"}`; request validation (422) is
 * `{"detail": [{"loc": [...], "msg": "..."}, ...]}`. Turn either into readable text.
 */
export function errorMessage(detail: unknown): string | undefined {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item !== 'object' || item === null || !('msg' in item)) return null
        const loc = 'loc' in item && Array.isArray(item.loc) ? item.loc.filter((part: unknown) => part !== 'body').join('.') : ''
        return loc ? `${loc}: ${String(item.msg)}` : String(item.msg)
      })
      .filter(Boolean)
    if (messages.length) return messages.join('; ')
  }
  return undefined
}
