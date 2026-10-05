import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components, operations } from '@/api/schema'

export type EventRow = components['schemas']['EventOut']
type EventPage = components['schemas']['EventPage']

/** The filters the events API accepts (all optional, AND-ed on the server). */
export type EventFilters = Omit<
  NonNullable<operations['list_events_api_uploads__upload_id__events_get']['parameters']['query']>,
  'cursor' | 'limit' | 'offset'
>

export const EVENTS_PAGE_SIZE = 75

const eventsKey = (uploadId: number, filters: EventFilters, page: number) => ['uploads', uploadId, 'events', filters, page]

/** Page N (1-based) of the filtered events (D86). If page N-1 is in the cache, its next_cursor
 *  continues by keyset (fast at any depth: the Next/Previous path); otherwise (a jump to a page
 *  number, or a reload of ?page=N) it uses an offset. */
export function useEvents(uploadId: number, filters: EventFilters, page: number) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: eventsKey(uploadId, filters, page),
    queryFn: () => {
      const previous = page > 1 ? queryClient.getQueryData<EventPage>(eventsKey(uploadId, filters, page - 1)) : undefined
      const position = page === 1 ? {} : previous?.next_cursor ? { cursor: previous.next_cursor }
        : { offset: (page - 1) * EVENTS_PAGE_SIZE }
      return unwrap(api.GET('/api/uploads/{upload_id}/events', {
        params: { path: { upload_id: uploadId }, query: { ...filters, ...position, limit: EVENTS_PAGE_SIZE } },
      }))
    },
    // Keep showing the current page (dimmed) while the next one loads: no flicker, no layout jump.
    placeholderData: keepPreviousData,
    staleTime: Infinity, // finished analyses don't change
  })
}

/** How many events match (asked once per filter, then cached). */
export function useEventCount(uploadId: number, filters: EventFilters) {
  return useQuery({
    queryKey: ['uploads', uploadId, 'events-count', filters],
    queryFn: () => unwrap(api.GET('/api/uploads/{upload_id}/events/count', {
      params: { path: { upload_id: uploadId }, query: filters },
    })),
    staleTime: Infinity,
  })
}

/** The dataset's first and last event (for time-range presets), from its stored summary. */
export function useDatasetBounds(uploadId: number) {
  return useQuery({
    queryKey: ['uploads', uploadId, 'bounds'],
    queryFn: () => unwrap(api.GET('/api/uploads/{upload_id}/summary', { params: { path: { upload_id: uploadId } } })),
    select: (summary) => ({ first: summary.stats.first_event, last: summary.stats.last_event }),
    staleTime: Infinity,
  })
}

/** Events per time bucket for the current filters (the Logs chart, D118). */
export function useEventHistogram(uploadId: number, filters: EventFilters) {
  return useQuery({
    queryKey: ['uploads', uploadId, 'events-histogram', filters],
    queryFn: () => unwrap(api.GET('/api/uploads/{upload_id}/events/histogram', {
      params: { path: { upload_id: uploadId }, query: filters },
    })),
    placeholderData: keepPreviousData,
    staleTime: Infinity,
  })
}
