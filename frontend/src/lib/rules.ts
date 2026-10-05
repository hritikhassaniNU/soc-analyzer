// Human-readable names for the backend's rule identifiers (app/detection/rules.py).
export const RULE_LABELS: Record<string, string> = {
  zscaler_threat: 'Zscaler threat',
  high_risk_allowed: 'High risk allowed',
  scripted_client: 'Scripted client',
  executable_download: 'Executable download',
}

export function ruleLabel(rule: string): string {
  return RULE_LABELS[rule] ?? rule
}

/** Rule scores >= this are treated as high priority in the UI (same threshold as high risk). */
export const HIGH_SCORE = 0.75
