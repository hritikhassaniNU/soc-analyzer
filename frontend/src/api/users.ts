import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components } from '@/api/schema'

export type UserListItem = components['schemas']['UserListItem']
export type UserProfile = components['schemas']['UserProfile']

/** Everyone seen in the logs, riskiest first. */
export function useUsers(q: string) {
  return useQuery({
    queryKey: ['users', { q }],
    queryFn: () => unwrap(api.GET('/api/users', { params: { query: q ? { q } : {} } })),
    placeholderData: keepPreviousData,
    staleTime: 15_000,
  })
}

export function useUserProfile(username: string) {
  return useQuery({
    queryKey: ['users', username],
    queryFn: () => unwrap(api.GET('/api/users/{username}', { params: { path: { username } } })),
  })
}

export function useUserReview(username: string) {
  return useQuery({
    queryKey: ['users', username, 'review'],
    queryFn: () => unwrap(api.GET('/api/users/{username}/review', { params: { path: { username } } })),
    staleTime: 30_000,
  })
}

/** Write a new review of this user now (~20 s with Claude; instant with the template). */
export function useGenerateUserReview(username: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST('/api/users/{username}/review', { params: { path: { username } } })),
    onSuccess: (review) => queryClient.setQueryData(['users', username, 'review'], review),
  })
}
