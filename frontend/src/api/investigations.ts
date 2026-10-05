import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components, operations } from '@/api/schema'

export type Investigation = components['schemas']['InvestigationItem']
export type InvestigationDetail = components['schemas']['InvestigationDetail']
export type CaseUpdate = Omit<components['schemas']['CaseUpdate'], 'expected_updated_at'>
export type InvestigationFilters = NonNullable<operations['list_investigations_api_investigations_get']['parameters']['query']>

/** The company-wide case queue, worst first. */
export function useInvestigations(filters: InvestigationFilters) {
  return useQuery({
    queryKey: ['investigations', filters],
    queryFn: () => unwrap(api.GET('/api/investigations', { params: { query: filters } })),
    placeholderData: keepPreviousData, // keep the table while a new filter loads
    staleTime: 15_000,
  })
}

export function useInvestigation(caseId: number) {
  return useQuery({
    queryKey: ['investigations', caseId],
    queryFn: () => unwrap(api.GET('/api/investigations/{case_id}', { params: { path: { case_id: caseId } } })),
  })
}

/** After a change: show the server's version of the case, refresh lists and the dashboard links. */
function useCaseChanged(caseId: number) {
  const queryClient = useQueryClient()
  return {
    onSuccess: (detail: InvestigationDetail) => {
      queryClient.setQueryData(['investigations', caseId], detail)
      return queryClient.invalidateQueries({ queryKey: ['investigations'], predicate: (q) => q.queryKey[1] !== caseId })
    },
    // 409 (someone else changed it) and other errors: reload the case so the page shows the truth.
    onError: () => queryClient.invalidateQueries({ queryKey: ['investigations', caseId] }),
  }
}

/** Change status / owner / verdict. Sends the updated_at the analyst saw (conflict check). */
export function useUpdateInvestigation(detail: InvestigationDetail) {
  return useMutation({
    mutationFn: (change: CaseUpdate) =>
      unwrap(api.PATCH('/api/investigations/{case_id}', {
        params: { path: { case_id: detail.id } },
        body: { ...change, expected_updated_at: detail.updated_at },
      })),
    ...useCaseChanged(detail.id),
  })
}

/** Append a note (notes are never edited or deleted). */
export function useAddNote(caseId: number) {
  return useMutation({
    mutationFn: (text: string) =>
      unwrap(api.POST('/api/investigations/{case_id}/notes', { params: { path: { case_id: caseId } }, body: { text } })),
    ...useCaseChanged(caseId),
  })
}
