/** Case workflow labels (the API's status values in words). */
export const STATUS_LABELS = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved' } as const

export const VERDICT_LABELS = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign (expected activity)',
} as const

export const NOTE_MAX_CHARS = 5000 // mirrors the backend's NOTE_MAX_CHARS

/** The AI's triage suggestion in words, and the case verdict it pre-selects when resolving
 *  ("needs more evidence" pre-selects nothing: the analyst decides). */
export const AI_VERDICT_LABELS = {
  likely_malicious: 'Likely malicious',
  likely_benign: 'Likely benign',
  needs_more_evidence: 'Needs more evidence',
} as const
export const AI_VERDICT_TO_CASE: Record<keyof typeof AI_VERDICT_LABELS, keyof typeof VERDICT_LABELS | null> = {
  likely_malicious: 'true_positive',
  likely_benign: 'benign',
  needs_more_evidence: null,
}

/** Status icon colors: blue open, violet investigating, green resolved. Never severity
 *  colors; the icon shape and the word always come with them. */
export const STATUS_ICON_CLASS = {
  open: 'text-status-open',
  investigating: 'text-status-investigating',
  resolved: 'text-status-success',
} as const
