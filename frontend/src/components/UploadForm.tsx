import { FileText, Upload as UploadIcon, X } from 'lucide-react'
import { useRef, useState, type DragEvent, type FormEvent } from 'react'
import { useCreateUpload, type UploadCreated } from '@/api/uploads'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'
import { formatBytes } from '@/lib/format'
import { HttpError } from '@/lib/queryClient'
import { cn } from '@/lib/utils'
import { ACCEPT, checkFile, EXTENSIONS_TEXT, FORMAT_CHOICES, type FormatChoice } from '@/lib/uploadRules'

// UTC first (most proxy exports use it), then every IANA zone the browser knows.
const TIMEZONES = ['UTC', ...Intl.supportedValuesOf('timeZone').filter((zone) => zone !== 'UTC')]
const SELECT_CLASS = 'h-8 rounded-lg border border-input bg-transparent px-2 text-sm dark:bg-input/30'

export default function UploadForm() {
  const [file, setFile] = useState<File | null>(null)
  const [timezone, setTimezone] = useState('UTC')
  const [format, setFormat] = useState<FormatChoice>('auto')
  const [fileError, setFileError] = useState<string | null>(null)
  const [fraction, setFraction] = useState(0)
  const [uploaded, setUploaded] = useState<UploadCreated | null>(null)
  const [dragging, setDragging] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)
  const create = useCreateUpload(setFraction)

  // Dropping or choosing only selects the file: the analyst checks it (and the options), then uploads.
  function choose(chosen: File | null) {
    setFile(chosen)
    setFileError(chosen ? checkFile(chosen) : null)
    setUploaded(null)
    create.reset() // clear a previous server error
  }

  function clear() {
    choose(null)
    if (fileInput.current) fileInput.current.value = '' // reset the native file input
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault() // otherwise the browser opens the file
    setDragging(false)
    if (!create.isPending) choose(event.dataTransfer.files[0] ?? null)
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file || checkFile(file)) return
    setFraction(0)
    create.mutate({ file, logTimezone: timezone, format }, {
      onSuccess: (upload) => {
        clear()
        setUploaded(upload)
      },
    })
  }

  const serverError = create.isError
    ? create.error instanceof HttpError && create.error.status !== 0
      ? create.error.message
      : "Can't reach the server. Try again."
    : null
  const percent = Math.round(fraction * 100)

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        // Leaving into a child (the button, the text) is not leaving the zone.
        onDragLeave={(e) => !e.currentTarget.contains(e.relatedTarget as Node | null) && setDragging(false)}
        onDrop={handleDrop}
        className={cn(
          'flex flex-col items-center gap-3 rounded-xl border-2 border-dashed px-4 py-12 text-center transition-colors',
          dragging ? 'border-primary bg-muted' : 'border-border',
        )}
      >
        <UploadIcon className="size-8 text-muted-foreground" aria-hidden />
        <div>
          <p className="section-title">Drop a log file here</p>
          {/* Exactly what is supported (D95): one log type, two formats, these file names. */}
          <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-left text-sm">
            <dt className="text-muted-foreground">Log type</dt><dd>Zscaler web proxy (NSS web log feed)</dd>
            <dt className="text-muted-foreground">Formats</dt><dd>CSV or JSON lines, plain or gzip-compressed (.gz)</dd>
            <dt className="text-muted-foreground">File names</dt><dd>{EXTENSIONS_TEXT}</dd>
          </dl>
        </div>
        <input
          id="log-file"
          ref={fileInput}
          type="file"
          accept={ACCEPT}
          className="sr-only"
          onChange={(e) => choose(e.target.files?.[0] ?? null)}
          disabled={create.isPending}
        />
        <Button type="button" onClick={() => fileInput.current?.click()} disabled={create.isPending}>
          Choose file
        </Button>

        {file && (
          <div className="flex max-w-full items-center gap-2 rounded-lg border bg-card px-3 py-2 text-sm">
            <FileText className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="truncate" title={file.name}>{file.name}</span>
            <span className="shrink-0 text-muted-foreground">{formatBytes(file.size)}</span>
            {!create.isPending && (
              <Button type="button" variant="ghost" size="icon-xs" aria-label="Remove file" onClick={clear}>
                <X />
              </Button>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="log-timezone">Log timezone</Label>
          <select id="log-timezone" value={timezone} onChange={(e) => setTimezone(e.target.value)}
                  disabled={create.isPending} className={cn(SELECT_CLASS, 'w-56')}>
            {TIMEZONES.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
          </select>
          <p className="text-xs text-muted-foreground">Only matters if the log's times have no timezone.</p>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="log-format">Format</Label>
          <select id="log-format" value={format} onChange={(e) => setFormat(e.target.value as FormatChoice)}
                  disabled={create.isPending} className={cn(SELECT_CLASS, 'w-40')}>
            {FORMAT_CHOICES.map((choice) => <option key={choice.value} value={choice.value}>{choice.option}</option>)}
          </select>
          <p className="text-xs text-muted-foreground">Detected from the content unless you choose.</p>
        </div>
        <Button type="submit" className="mb-5 sm:ml-auto" disabled={!file || !!fileError || create.isPending}>
          {create.isPending ? 'Uploading…' : 'Upload'}
        </Button>
      </div>

      {create.isPending && (
        <div className="flex flex-col gap-1" aria-live="polite">
          <Progress value={percent} aria-label="Upload progress" />
          <p className="text-xs text-muted-foreground">
            {percent < 100 ? `Uploading… ${percent}%` : 'Checking and storing on the server…'}
          </p>
        </div>
      )}

      {(fileError || serverError) && (
        <p role="alert" className="text-sm text-destructive">{fileError ?? serverError}</p>
      )}
      {uploaded && (
        <div className="flex flex-col gap-1 text-sm" aria-live="polite">
          <p className="text-muted-foreground">
            Uploaded {uploaded.filename}. The scan has started; see its status below.
          </p>
          {uploaded.previous_uploads > 0 && (
            <p role="status" className="rounded-lg border px-3 py-2">
              This exact file (same SHA-256) was already uploaded {uploaded.previous_uploads}{' '}
              {uploaded.previous_uploads === 1 ? 'time' : 'times'}. It will be scanned again; its incidents
              won't be duplicated in Investigations.
            </p>
          )}
        </div>
      )}
    </form>
  )
}
