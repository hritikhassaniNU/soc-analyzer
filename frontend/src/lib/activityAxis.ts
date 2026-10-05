/** X-axis ticks for an activity chart: midnights (UTC) between the first and last point, thinned
 *  to at most `max` ticks so labels never collide. Times in milliseconds. */
export function midnightTicks(firstMs: number, lastMs: number, max = 8): number[] {
  const DAY = 86_400_000
  const ticks: number[] = []
  for (let t = Math.ceil(firstMs / DAY) * DAY; t <= lastMs; t += DAY) ticks.push(t)
  const step = Math.max(1, Math.ceil(ticks.length / max))
  return ticks.filter((_, i) => i % step === 0)
}
