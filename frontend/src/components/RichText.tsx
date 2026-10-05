import { Link } from 'react-router'
import { splitEntities } from '@/lib/richText'
import { userPath } from '@/lib/users'

/** Text with known usernames linked to their profile and domains in mono. Plain text only: the
 *  input can quote log-derived names, so nothing is ever rendered as HTML. */
export default function RichText({ text, users }: { text: string; users: readonly string[] }) {
  return (
    <>
      {splitEntities(text, users).map((part, n) =>
        part.kind === 'user' ? (
          <Link key={n} to={userPath(part.value.toLowerCase())} className="font-medium underline-offset-2 hover:underline">
            {part.value}
          </Link>
        ) : part.kind === 'domain' ? (
          <span key={n} className="tech break-all">{part.value}</span>
        ) : (
          part.value
        ),
      )}
    </>
  )
}
