import { Link } from 'react-router'

export default function NotFoundPage() {
  return (
    <main className="mx-auto max-w-xl p-8">
      <h1 className="page-title">Page not found</h1>
      <Link to="/" className="text-primary underline underline-offset-4">
        Back to home
      </Link>
    </main>
  )
}
