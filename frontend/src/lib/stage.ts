// What the worker is doing, derived from its progress. The ranges mirror the backend:
// pass 1 = 0-70 (app/pipeline/pass1.py), pass 2 = 70-95 (pass2.py), summary = 95-99 (narrate.py).
// One source of truth (progress) instead of a second field to keep in sync.
const STAGES: [upTo: number, label: string][] = [
  [70, 'Reading and checking the file'],
  [95, 'Detecting threats'],
  [100, 'Writing the summary'],
]

export function stageLabel(progress: number): string {
  return (STAGES.find(([upTo]) => progress < upTo) ?? STAGES[STAGES.length - 1])[1]
}
