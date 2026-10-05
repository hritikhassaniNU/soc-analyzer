/** Split model- or log-derived text into plain parts, known usernames and domain names, so the UI
 *  can link users to their profile and set domains in mono. Never produces HTML: React renders
 *  every part as text. */
export type Part = { kind: 'text' | 'user' | 'domain'; value: string }

// A hostname with at least one dot and a short letters-only TLD (mega.nz, cdn-update-check.xyz).
// 2-6 letters: long "TLDs" are almost always threat names like Trojan.GenericKD (D94).
const DOMAIN = String.raw`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}`
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export function splitEntities(text: string, users: readonly string[]): Part[] {
  const names = [...new Set(users)].filter(Boolean).sort((a, b) => b.length - a.length).map(escape)
  // Users first (longest first), as whole words; "jdoe's" still matches "jdoe".
  const pattern = new RegExp(
    `${names.length ? `(?<user>\\b(?:${names.join('|')})\\b)|` : ''}(?<domain>\\b${DOMAIN}\\b)`,
    'gi',
  )
  const parts: Part[] = []
  let last = 0
  for (const m of text.matchAll(pattern)) {
    const start = m.index ?? 0
    if (start > last) parts.push({ kind: 'text', value: text.slice(last, start) })
    parts.push({ kind: m.groups?.user ? 'user' : 'domain', value: m[0] })
    last = start + m[0].length
  }
  if (last < text.length) parts.push({ kind: 'text', value: text.slice(last) })
  return parts
}
