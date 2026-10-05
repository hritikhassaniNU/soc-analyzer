import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components } from '@/api/schema'
import { HttpError } from '@/lib/queryClient'

export type User = components['schemas']['UserOut']

export const meQueryKey = ['me'] as const
export const loginMutationKey = ['login'] as const

/**
 * `Basic base64(username:password)`, UTF-8 encoded to match the backend parser.
 * Plain btoa() is wrong here: it encodes "é" as Latin-1 (0xE9, which then fails
 * login silently) and throws on characters like "€" or emoji.
 */
export function basicAuthHeader(username: string, password: string): string {
  const bytes = new TextEncoder().encode(`${username}:${password}`)
  return 'Basic ' + btoa(String.fromCharCode(...bytes))
}

/**
 * Who is logged in? Returns the user, or `null` when not logged in (401).
 * Any other failure (server down, 500) stays an error, so an outage is never
 * mistaken for "logged out".
 */
export function useMe() {
  return useQuery({
    queryKey: meQueryKey,
    queryFn: async (): Promise<User | null> => {
      try {
        return await unwrap(api.GET('/api/me'))
      } catch (error) {
        if (error instanceof HttpError && error.status === 401) return null
        throw error
      }
    },
    staleTime: Infinity, // only changes on login/logout, which update the cache directly
  })
}

export function useLogin() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationKey: loginMutationKey, // lets the global 401 handler skip "wrong password"
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      unwrap(
        api.POST('/api/login', {
          headers: { Authorization: basicAuthHeader(username, password) },
        }),
      ),
    // The response already contains the user: no extra /api/me request needed.
    onSuccess: (user) => queryClient.setQueryData(meQueryKey, user),
  })
}

export function useLogout() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST('/api/logout')),
    // Even if the request fails, forget everything locally: no data from this session lingers.
    onSettled: () => {
      queryClient.clear()
      queryClient.setQueryData(meQueryKey, null)
    },
  })
}
