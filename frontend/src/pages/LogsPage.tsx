import { useSearchParams } from 'react-router'
import EventFiltersBar from '@/components/events/EventFiltersBar'
import EventsHistogram from '@/components/events/EventsHistogram'
import EventsTable from '@/components/events/EventsTable'
import DataPage from '@/components/layout/DataPage'
import { filtersFromParams, paramsWithFilters } from '@/lib/eventFilters'

/** One dataset's events with filters (the per-file overview tab was removed at the user's request, D82). */
export default function LogsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = filtersFromParams(searchParams) // event filters live in the URL, next to ?upload=
  const filtersKey = JSON.stringify(filters) // new filters -> fresh table (back to page 1) and inputs

  return (
    <DataPage title="Logs">
      {(upload) => (
        <div className="flex flex-col gap-4">
          {/* Sibling keys must be unique: a shared key once rendered two filter bars. */}
          <EventFiltersBar
            uploadId={upload.id}
            key={`filters-${upload.id}-${filtersKey}`}
            filters={filters}
            onApply={(next) => setSearchParams(paramsWithFilters(searchParams, next))}
          />
          <EventsHistogram uploadId={upload.id} filters={filters}
                           onZoom={(start, end) => setSearchParams(paramsWithFilters(searchParams, { ...filters, start, end }))} />
          <EventsTable key={`table-${upload.id}-${filtersKey}`} uploadId={upload.id} filters={filters}
                       page={Number(searchParams.get('page') ?? '1') || 1} onPage={(n) => {
                         const next = new URLSearchParams(searchParams)
                         if (n > 1) next.set('page', String(n))
                         else next.delete('page')
                         setSearchParams(next)
                       }} />
        </div>
      )}
    </DataPage>
  )
}
