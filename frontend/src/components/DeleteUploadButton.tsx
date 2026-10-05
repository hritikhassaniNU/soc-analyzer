import { Trash2 } from 'lucide-react'
import { useDeleteUpload } from '@/api/uploads'
import { Button } from '@/components/ui/button'
import { HttpError } from '@/lib/queryClient'

/** The one Delete button: same look (destructive, trash icon), same confirmation and same
 *  error handling wherever an upload can be deleted (Upload Logs list, upload details). */
export default function DeleteUploadButton({ upload, onDeleted }: {
  upload: { id: number; filename: string }
  onDeleted?: () => void
}) {
  const remove = useDeleteUpload()

  function handleDelete() {
    // Irreversible: always ask first.
    if (!window.confirm(`Delete ${upload.filename}? This removes the file and its analysis. This can't be undone.`)) return
    remove.mutate(upload.id, { onSuccess: () => onDeleted?.() })
  }

  const error = remove.isError
    ? remove.error instanceof HttpError && remove.error.status !== 0 ? remove.error.message : "Can't reach the server"
    : null

  return (
    <span className="inline-flex flex-col items-end gap-1">
      <Button variant="destructive" size="sm" onClick={handleDelete} disabled={remove.isPending}
              aria-label={`Delete ${upload.filename}`}>
        <Trash2 /> {remove.isPending ? 'Deleting…' : 'Delete'}
      </Button>
      {error && <span role="alert" className="max-w-56 text-right text-xs text-destructive">{error}</span>}
    </span>
  )
}
