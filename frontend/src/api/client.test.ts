import { describe, expect, it } from 'vitest'
import { errorMessage } from '@/api/client'

describe('errorMessage', () => {
  it('keeps our own string messages', () => {
    expect(errorMessage('Investigation not found')).toBe('Investigation not found')
  })

  it('turns FastAPI validation lists into readable text (not "[object Object]")', () => {
    const detail = [
      { loc: ['body', 'text'], msg: 'String should have at most 5000 characters', type: 'string_too_long' },
      { loc: ['body', 'status'], msg: "Input should be 'open', 'investigating' or 'resolved'" },
    ]
    expect(errorMessage(detail)).toBe(
      "text: String should have at most 5000 characters; status: Input should be 'open', 'investigating' or 'resolved'",
    )
  })

  it('gives up on shapes it does not know (caller falls back to the status text)', () => {
    expect(errorMessage(undefined)).toBeUndefined()
    expect(errorMessage([{ nope: 1 }])).toBeUndefined()
    expect(errorMessage({ a: 1 })).toBeUndefined()
  })
})
