import { type FormEvent, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { type Upload, useUploads } from '@/api/uploads'
import DeleteUploadButton from '@/components/DeleteUploadButton'
import MultiSelect from '@/components/MultiSelect'
import Pagination from '@/components/Pagination'
import SortHeader from '@/components/SortHeader'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import { stageLabel } from '@/lib/stage'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatBytes, formatRelative } from '@/lib/format'
import { paginate } from '@/lib/pagination'
import { paramsForSort, sortFrom, sortRows } from '@/lib/sorting'
import { applyUploadFilters, UPLOAD_FORMATS, UPLOAD_STATUSES, uploadFiltersFrom } from '@/lib/uploadFilters'
import { formatLabel } from '@/lib/uploadRules'

export function StatusBadge({ upload }: { upload: Upload }) {
  switch (upload.status) {
    case 'queued':
      return <Badge variant="outline" className="text-muted-foreground">Queued</Badge>
    case 'processing':
      return (
        <div className="flex min-w-28 flex-col gap-1">
          <Badge className="bg-status-open/15 text-status-open">Processing {upload.progress}%</Badge>
          <Progress value={upload.progress} aria-label={`Analysis progress ${upload.progress}%`} />
          <span className="text-xs text-muted-foreground">{stageLabel(upload.progress)}…</span>
        </div>
      )
    case 'done': // shown as "Scanned"; the API status stays 'done'
      // Soft tints from the status tokens (D105), like the Failed badge: calm, not loud.
      return <Badge className="bg-status-success/15 text-status-success">Scanned</Badge>
    default:
      return <Badge variant="destructive">Failed</Badge>
  }
}

export default function UploadsTable() {
  const uploads = useUploads() // polls every 2 s while anything is queued/processing
  const [params, setParams] = useSearchParams() // ?page= (25 per page, like every list: D95)
  const f = uploadFiltersFrom(params) // ?q=&status=&format= (D100)
  const [search, setSearch] = useState(f.q)

  function set(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (key !== 'page') next.delete('page') // a new filter starts at page 1
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next)
  }
  function submitSearch(event: FormEvent) {
    event.preventDefault()
    set('q', search.trim())
  }

  if (uploads.isPending) return <p className="text-sm text-muted-foreground">Loading…</p>
  if (uploads.isError) {
    return (
      <div className="flex items-center gap-3 text-sm text-muted-foreground">
        Can't load uploads.
        <Button variant="outline" size="sm" onClick={() => uploads.refetch()}>
          Retry
        </Button>
      </div>
    )
  }
  if (uploads.data.length === 0) {
    return <p className="text-sm text-muted-foreground">No uploads yet. Upload a log file above.</p>
  }

  const all = uploads.data
  const shown = applyUploadFilters(all, f)
  // Sorting (D111): default newest upload first (the server's order).
  const sorting = sortFrom(params, ['uploaded', 'lines'] as const)
  const sorted = sorting.sort === 'lines' ? sortRows(shown, (u) => u.line_count, sorting.dir, (a, b) => b.id - a.id)
    : sorting.dir === 'asc' ? [...shown].reverse() : shown
  const paged = paginate(sorted, Number(params.get('page') ?? '1'))
  const filtered = !!f.q || f.statuses.length > 0 || f.formats.length > 0
  const count = (key: 'status' | 'format', value: string) => all.filter((u) => u[key] === value).length
  return (
    // The table scrolls sideways inside its card on narrow screens; the page never does.
    <div className="flex flex-col gap-3">
    <div className="flex flex-wrap items-center gap-2">
      <form onSubmit={submitSearch} role="search">
        <Input aria-label="Search uploads" placeholder="Search file name or id…" value={search}
               onChange={(e) => setSearch(e.target.value)} className="h-9 w-64" />
      </form>
      <MultiSelect label="Status" allLabel="All status" selected={f.statuses} onChange={(v) => set('status', v.join(','))}
                   options={Object.entries(UPLOAD_STATUSES).map(([value, label]) => ({ value, label, count: count('status', value) }))} />
      <MultiSelect label="Format" allLabel="All formats" selected={f.formats} onChange={(v) => set('format', v.join(','))}
                   options={Object.entries(UPLOAD_FORMATS).map(([value, label]) => ({ value, label, count: count('format', value) }))} />
      {filtered && (
        <button type="button" className="h-9 px-2 text-sm text-muted-foreground hover:text-foreground"
                onClick={() => { setSearch(''); setParams(new URLSearchParams()) }}>Clear filters</button>
      )}
      <span className="meta ml-auto">{shown.length} of {all.length} uploads</span>
    </div>
    {shown.length === 0 ? <p className="text-sm text-muted-foreground">No uploads match these filters.</p> : (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>File</TableHead>
            <SortHeader label="Uploaded" active={(sorting.sort ?? 'uploaded') === 'uploaded'} dir={sorting.dir}
                        onSort={() => setParams(paramsForSort(params, sorting, 'uploaded', 'uploaded'))} />
            <TableHead>Status</TableHead>
            <SortHeader label="Lines" active={sorting.sort === 'lines'} dir={sorting.dir}
                        onSort={() => setParams(paramsForSort(params, sorting, 'lines', 'uploaded'))} />
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {paged.items.map((upload) => (
            <TableRow key={upload.id} className="align-top">
              <TableCell>
                {/* Filenames are user input: rendered as text by React (escaped), never as HTML. */}
                <div className="font-medium">{upload.filename}</div>
                <div className="text-xs text-muted-foreground">{formatBytes(upload.size_bytes)} · {formatLabel(upload.format)}</div>
              </TableCell>
              <TableCell>
                <div title={new Date(upload.created_at).toLocaleString()}>
                  {formatRelative(upload.created_at)}
                </div>
                <div className="text-xs text-muted-foreground">{upload.uploaded_by ?? 'deleted user'}</div>
              </TableCell>
              <TableCell className="whitespace-normal">
                <StatusBadge upload={upload} />
                {upload.status === 'failed' && upload.error && (
                  <p className="mt-1 max-w-xs text-xs text-destructive">{upload.error}</p>
                )}
              </TableCell>
              <TableCell className="text-sm">
                {upload.line_count === null ? (
                  <span className="text-muted-foreground">—</span>
                ) : (
                  <>
                    {upload.line_count.toLocaleString()}
                    {!!upload.bad_line_count && (
                      <span className="text-muted-foreground"> · {upload.bad_line_count.toLocaleString()} bad</span>
                    )}
                  </>
                )}
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-2">
                  {upload.status === 'done' && (
                    <Button asChild size="sm">
                      <Link to={`/logs?upload=${upload.id}`}>Open</Link>
                    </Button>
                  )}
                  <Button asChild variant="outline" size="sm">
                    <Link to={`/uploads/${upload.id}`}>Details</Link>
                  </Button>
                  <DeleteUploadButton upload={upload} />
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
    )}
    {paged.pages > 1 && (
      <Pagination page={paged.page} pages={paged.pages} from={paged.from} to={paged.to} total={paged.total} noun="uploads"
                  onPage={(n) => set('page', n > 1 ? String(n) : '')} />
    )}
    </div>
  )
}
