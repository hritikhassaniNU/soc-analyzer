/** Detection Rules page: layer names and the confirmation shown before switching a detector off. */
export const LAYER_LABELS = { rule: 'Rule', stat: 'Statistical', ml: 'Machine learning', ai: 'AI (Claude)' } as const

export const LAYER_HELP = {
  rule: 'Checks each log line on its own.',
  stat: "Compares behavior with the user's own history (or everyone's) across the whole file.",
  ml: 'IsolationForest on per-user hourly behavior; evidence only, never changes risk.',
  ai: 'Claude judges rare domain names (only names, categories and counts are sent); runs only with an API key.',
} as const

/** What stops being found if this detector is switched off (for the confirmation). */
export function disableWarning(name: string, summary: string): string {
  return (
    `Switch off "${name}"?\n\n` +
    `New scans will no longer find: ${summary}\n\n` +
    'Existing results are kept. Your name and the time are recorded on the Detection Rules page.'
  )
}
