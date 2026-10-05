/** Link to a log user's profile (usernames come from logs: always encode). */
export function userPath(username: string): string {
  return `/users/${encodeURIComponent(username)}`
}
