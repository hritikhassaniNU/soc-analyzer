import { Bot } from 'lucide-react'

/** "AI-generated" under text Claude wrote. Template text gets no label at all (D138): the
 *  response is shown on its own. (The model name is stored for auditing, not shown.) */
export function SourceLabel({ ai }: { ai: boolean }) {
  if (!ai) return null
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <Bot className="size-3.5" aria-hidden />
      AI-generated
    </span>
  )
}
