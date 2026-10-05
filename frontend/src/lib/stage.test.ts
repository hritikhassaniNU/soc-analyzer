import { describe, expect, it } from 'vitest'
import { stageLabel } from '@/lib/stage'

describe('stageLabel', () => {
  it.each([
    [0, 'Reading and checking the file'],
    [69, 'Reading and checking the file'],
    [70, 'Detecting threats'],   // pass 1 finished
    [94, 'Detecting threats'],
    [95, 'Writing the summary'], // pass 2 finished
    [99, 'Writing the summary'],
  ])('%i%% → %s', (progress, label) => {
    expect(stageLabel(progress)).toBe(label)
  })
})
