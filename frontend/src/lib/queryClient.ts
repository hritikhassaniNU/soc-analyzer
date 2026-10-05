import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query'

/** Error carrying the HTTP status, so retry logic (and pages) can tell 4xx from other failures. */
export class HttpError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

/**
 * Session expired mid-use (any API call returns 401): mark the user as logged out.
 * The route guard then redirects to /login. A 401 from the login mutation itself
 * means "wrong password", not "session expired", so it's skipped.
 */
function handleUnauthorized(error: unknown, mutationKey?: readonly unknown[]) {
  if (!(error instanceof HttpError) || error.status !== 401) return
  if (mutationKey?.[0] === 'login') return
  queryClient.setQueryData(['me'], null)
}

export const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({ onError: (error) => handleUnauthorized(error) }),
  mutationCache: new MutationCache({
    onError: (error, _vars, _ctx, mutation) => handleUnauthorized(error, mutation.options.mutationKey),
  }),
  defaultOptions: {
    queries: {
      // A 4xx (401, 404, ...) won't fix itself by retrying; a network blip or 5xx might.
      retry: (failureCount, error) =>
        !(error instanceof HttpError && error.status < 500) && failureCount < 2,
      // Results only change when an upload finishes, which we poll for explicitly.
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
})
