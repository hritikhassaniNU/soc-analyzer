import { useState, type FormEvent } from 'react'
import { type InvestigationDetail, useAddNote } from '@/api/investigations'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { formatDateTime, formatRelative } from '@/lib/format'
import { NOTE_MAX_CHARS } from '@/lib/investigations'
import { HttpError } from '@/lib/queryClient'

/** Append-only analyst notes: written once, never edited or deleted (add a new note to correct one). */
export default function CaseNotes({ d }: { d: InvestigationDetail }) {
  const [text, setText] = useState('')
  const add = useAddNote(d.id)

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!text.trim()) return
    add.mutate(text, { onSuccess: () => setText('') })
  }

  const error = add.isError
    ? add.error instanceof HttpError && add.error.status !== 0 ? add.error.message : "Can't reach the server. Try again."
    : null

  return (
    <section className="flex flex-col gap-4 rounded-xl border bg-card p-6">
      <h2 className="section-title">Notes</h2>
      {d.notes.length === 0 ? (
        <p className="text-sm text-muted-foreground">No notes yet.</p>
      ) : (
        <ol className="flex flex-col gap-3">
          {d.notes.map((n) => (
            <li key={n.id} className="rounded-lg border px-4 py-3">
              <p className="text-xs text-muted-foreground">
                <span className="font-medium text-foreground">{n.author ?? 'Deleted account'}</span>
                {' · '}
                <time dateTime={n.created_at} title={formatDateTime(n.created_at)}>{formatRelative(n.created_at)}</time>
              </p>
              {/* Plain text, line breaks kept. */}
              <p className="mt-1 text-sm break-words whitespace-pre-wrap">{n.text}</p>
            </li>
          ))}
        </ol>
      )}

      <form onSubmit={handleSubmit} className="flex flex-col gap-2">
        <Label htmlFor="case-note">Add a note</Label>
        <textarea
          id="case-note"
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={NOTE_MAX_CHARS}
          rows={3}
          placeholder="What did you check, and what did you find?"
          className="rounded-lg border border-input bg-transparent px-3 py-2 text-sm dark:bg-input/30"
          disabled={add.isPending}
        />
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">Notes can't be edited or deleted once added.</p>
          <Button type="submit" size="sm" disabled={!text.trim() || add.isPending}>
            {add.isPending ? 'Adding…' : 'Add note'}
          </Button>
        </div>
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      </form>
    </section>
  )
}
