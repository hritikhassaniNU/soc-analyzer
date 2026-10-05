import { ArrowLeft, Check, Copy, ScrollText } from 'lucide-react'
import { useState } from 'react'
import { Link, Navigate, useNavigate, useParams, useSearchParams } from 'react-router'
import { useUpload } from '@/api/uploads'
import DeleteUploadButton from '@/components/DeleteUploadButton'
import { StatusBadge } from '@/components/UploadsTable'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { filtersFromParams, paramsWithFilters } from '@/lib/eventFilters'
import { formatBytes, formatDateTime } from '@/lib/format'
import { kindLabel } from '@/lib/incidents'
import { formatLabel } from '@/lib/uploadRules'
import { HttpError } from '@/lib/queryClient'
import NotFoundPage from '@/pages/NotFoundPage'

/** One upload's details: file info, parse results, bad-line samples. Its analysis lives on the
 *  Dashboard / Investigations / Logs pages (selected there with ?upload=). */
export default function UploadDetailPage() {
  const { uploadId } = useParams()
  const [searchParams] = useSearchParams()
  const id = Number(uploadId)
  if (!Number.isInteger(id) || id <= 0) return <NotFoundPage />
  if (searchParams.get('tab') === 'events') {
    // Older links opened events here: send them to Logs with the same filters.
    const next = paramsWithFilters(new URLSearchParams({ upload: String(id) }), filtersFromParams(searchParams))
    return <Navigate to={`/logs?${next}`} replace />
  }
  return <UploadDetails id={id} />
}

function UploadDetails({ id }: { id: number }) {
  const navigate = useNavigate()
  const upload = useUpload(id) // polls while queued/processing

  if (upload.isPending) return <PageShell>Loading…</PageShell>
  if (upload.isError) {
    const notFound = upload.error instanceof HttpError && upload.error.status === 404
    return (
      <PageShell>
        <p>{notFound ? 'Upload not found. It may have been deleted.' : "Can't load this upload."}</p>
        {!notFound && (
          <Button variant="outline" size="sm" onClick={() => upload.refetch()}>
            Retry
          </Button>
        )}
      </PageShell>
    )
  }

  const u = upload.data
  const validPercent =
    u.line_count && u.bad_line_count !== null
      ? (((u.line_count - u.bad_line_count) / u.line_count) * 100).toFixed(1)
      : null

  return (
    <PageShell>
      <div className="flex flex-wrap items-center gap-3">
        {/* User-supplied filename: rendered as text (React escapes it). */}
        <h1 className="page-title break-all">{u.filename}</h1>
        <StatusBadge upload={u} />
      </div>

      {u.status === 'failed' && u.error && (
        <div role="alert" className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Analysis failed: {u.error}
        </div>
      )}

      <div className="flex flex-wrap items-start justify-between gap-2">
        {u.status === 'done' ? (
          <Button asChild size="sm">
            <Link to={`/logs?upload=${id}`}><ScrollText />Open in Logs</Link>
          </Button>
        ) : <span />}
        <DeleteUploadButton upload={u} onDeleted={() => navigate('/uploads')} />
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 text-sm">
              <dt className="text-muted-foreground">Size</dt>
              <dd>{formatBytes(u.size_bytes)}</dd>
              <dt className="text-muted-foreground">Uploaded by</dt>
              <dd>{u.uploaded_by ?? 'deleted user'}</dd>
              <dt className="text-muted-foreground">Uploaded at</dt>
              <dd>{formatDateTime(u.created_at)}</dd>
              <dt className="text-muted-foreground">Completed at</dt>
              <dd>{u.completed_at ? formatDateTime(u.completed_at) : '—'}</dd>
              <dt className="text-muted-foreground">Detectors off</dt>
              <dd>
                {/* Snapshot from when this file was scanned (Detection Rules switches affect new scans only). */}
                {u.disabled_detectors.length ? u.disabled_detectors.map(kindLabel).join(', ') : 'None (all detectors ran)'}
              </dd>
              <dt className="text-muted-foreground">Log timezone</dt>
              <dd>{u.log_timezone}</dd>
              <dt className="text-muted-foreground">Format</dt>
              <dd>{formatLabel(u.format)}</dd>
              <dt className="text-muted-foreground">SHA-256</dt>
              <dd className="flex items-start gap-2">
                <code className="tech break-all">{u.sha256}</code>
                <CopyButton text={u.sha256} />
              </dd>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Parse results</CardTitle>
          </CardHeader>
          <CardContent>
            {u.line_count === null ? (
              <p className="text-sm text-muted-foreground">
                {u.status === 'failed' ? 'No results: the analysis failed.' : 'Available when the analysis finishes.'}
              </p>
            ) : (
              <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-2 text-sm">
                <dt className="text-muted-foreground">Lines</dt>
                <dd>{u.line_count.toLocaleString()}</dd>
                <dt className="text-muted-foreground">Bad lines</dt>
                <dd>{(u.bad_line_count ?? 0).toLocaleString()}</dd>
                <dt className="text-muted-foreground">Valid</dt>
                <dd>{validPercent}%</dd>
              </dl>
            )}
          </CardContent>
        </Card>
      </div>

      {u.bad_line_samples.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Bad-line samples (first {u.bad_line_samples.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">Line</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>Raw line</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {u.bad_line_samples.map((sample) => (
                    <TableRow key={sample.line_no} className="align-top">
                      <TableCell>{sample.line_no.toLocaleString()}</TableCell>
                      <TableCell className="whitespace-normal">{sample.reason}</TableCell>
                      <TableCell className="whitespace-normal">
                        {/* Attacker-controlled log text: plain text only (React escapes it);
                            never dangerouslySetInnerHTML. */}
                        <code className="text-xs break-all">{sample.raw}</code>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </PageShell>
  )
}

function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <Link to="/uploads" className="flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> Back to uploads
      </Link>
      {children}
    </main>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(text) // works on localhost and HTTPS
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <Button variant="ghost" size="icon-sm" onClick={copy} aria-label="Copy SHA-256">
      {copied ? <Check /> : <Copy />}
    </Button>
  )
}
