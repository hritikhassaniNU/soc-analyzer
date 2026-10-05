import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components } from '@/api/schema'

export type Dashboard = components['schemas']['Dashboard']
export type RiskyUser = components['schemas']['RiskyUser']
export type DashboardIncident = components['schemas']['DashboardIncident']

/** The company-wide picture: every completed upload, each incident counted once. */
export function useDashboard() {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: () => unwrap(api.GET('/api/dashboard')),
    staleTime: 30_000, // new analyses finish in the background: refresh on return after 30 s
  })
}

export type Review = components['schemas']['ReviewOut']

/** The latest company-wide review (null until one is written). */
export function useReview() {
  return useQuery({
    queryKey: ['dashboard', 'review'],
    queryFn: () => unwrap(api.GET('/api/dashboard/review')),
    staleTime: 30_000,
  })
}

/** Write a new review now (~20 s with Claude; instant with the template). */
export function useGenerateReview() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST('/api/dashboard/review')),
    onSuccess: (review) => queryClient.setQueryData(['dashboard', 'review'], review),
  })
}
