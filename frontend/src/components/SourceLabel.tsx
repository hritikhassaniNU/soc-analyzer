import { Bot, FileText } from 'lucide-react'

/** Who wrote the text: AI or the template. (The model name is stored for auditing, not shown.) */
export function SourceLabel({ ai }: { ai: boolean }) {
  const Icon = ai ? Bot : FileText
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <Icon className="size-3.5" aria-hidden />
      {ai ? 'AI-generated' : 'Template summary (no AI)'}
    </span>
  )
}
