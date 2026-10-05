import { describe, expect, it } from 'vitest'
import { disableWarning } from '@/lib/detectors'

describe('disableWarning', () => {
  it('says what stops being found and that old results stay', () => {
    const text = disableWarning('Beaconing', 'Machine-regular requests to a rarely used destination.')
    expect(text).toContain('Switch off "Beaconing"?')
    expect(text).toContain('New scans will no longer find: Machine-regular requests')
    expect(text).toContain('Existing results are kept')
  })
})
