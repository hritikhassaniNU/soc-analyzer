// Convenience checks before sending a file. The server enforces the real rules
// (the file dialog's `accept` and these checks can both be bypassed).
export const ALLOWED_EXTENSIONS = ['.log', '.txt', '.csv', '.json', '.jsonl', '.ndjson']

/** What the format field accepts: detect from the content, or force one. */
// `label`: for upload rows; `option`: dropdown text. What's supported is stated once, in the
// drop zone, not repeated in every option.
export const FORMAT_CHOICES = [
  { value: 'auto', label: 'Auto-detect', option: 'Auto-detect' },
  { value: 'csv', label: 'CSV', option: 'CSV' },
  { value: 'json', label: 'JSON lines', option: 'JSON lines' },
] as const
export type FormatChoice = (typeof FORMAT_CHOICES)[number]['value']

/** 'json' -> 'JSON lines', 'csv' -> 'CSV' (for display). */
export function formatLabel(format: string): string {
  return FORMAT_CHOICES.find((c) => c.value === format)?.label ?? format
}
export const MAX_UPLOAD_MB = 1024 // mirrors the backend's max_upload_mb setting (compressed size for .gz)

/** "a, b or c": for help text. */
export const EXTENSIONS_TEXT = `${ALLOWED_EXTENSIONS.slice(0, -1).join(', ')} or ${ALLOWED_EXTENSIONS.at(-1)}`

/** For the file dialog's `accept`: every extension, plain or gzip-compressed. */
export const ACCEPT = [...ALLOWED_EXTENSIONS, '.gz'].join(',')

/** A user-facing reason the file can't be uploaded, or null if it looks fine. */
export function checkFile(file: { name: string; size: number }): string | null {
  // Optionally gzip-compressed: "events.jsonl.gz" (the server detects compression from the content).
  const name = file.name.toLowerCase().replace(/\.gz$/, '')
  if (!ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext))) {
    return `Unsupported file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')} (optionally .gz)`
  }
  if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
    return `File is larger than ${MAX_UPLOAD_MB} MB`
  }
  return null
}
