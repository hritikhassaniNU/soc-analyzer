import { describe, expect, it } from 'vitest'
import { userPath } from '@/lib/users'

describe('userPath', () => {
  it('encodes log-derived usernames so they stay one path segment', () => {
    expect(userPath('jdoe')).toBe('/users/jdoe')
    expect(userPath('a/b?c#d')).toBe('/users/a%2Fb%3Fc%23d')
    expect(userPath('j.doe@acme.com')).toBe('/users/j.doe%40acme.com')
  })
})
