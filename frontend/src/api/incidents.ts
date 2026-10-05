import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components } from '@/api/schema'

export type IncidentList = components['schemas']['IncidentList']
export type Incident = components['schemas']['IncidentOut']
export type Finding = components['schemas']['AnomalyOut']
export type Priority = Incident['priority']

/**
 * Incidents worst first, each with its findings. Medium and above by default; `showLow` also asks
 * for the low ones (a big file can have many). `counts` always cover every priority.
 */
export function useIncidents(uploadId: number, showLow: boolean, enabled: boolean) {
  const minPriority: Priority = showLow ? 'low' : 'medium'
  return useQuery({
    queryKey: ['uploads', uploadId, 'incidents', minPriority],
    queryFn: () =>
      unwrap(
        api.GET('/api/uploads/{upload_id}/incidents', {
          params: { path: { upload_id: uploadId }, query: { min_priority: minPriority } },
        }),
      ),
    enabled,
    placeholderData: keepPreviousData, // keep the list visible while the low ones load
    staleTime: Infinity, // finished analyses don't change
  })
}
