import { Navigate, Outlet, useLocation } from 'react-router'
import { useMe } from '@/api/auth'
import { Button } from '@/components/ui/button'

/** Where to return after login. Kept in router state (in-app only), never a ?next= URL param. */
export type LoginRedirectState = { from?: string }

/**
 * Layout route guarding every page nested inside it.
 * UX only: the real protection is the backend answering 401 without a valid session.
 */
export default function RequireAuth() {
  const me = useMe()
  const location = useLocation()

  if (me.isPending) {
    return <CenteredMessage>Loading…</CenteredMessage>
  }

  // Server down / 500: NOT the same as logged out, so don't send them to the login page.
  if (me.isError) {
    return (
      <CenteredMessage>
        <p>Can't reach the server.</p>
        <Button variant="outline" onClick={() => me.refetch()}>
          Retry
        </Button>
      </CenteredMessage>
    )
  }

  if (me.data === null) {
    const state: LoginRedirectState = { from: location.pathname + location.search }
    // replace: Back won't bounce between this page and /login.
    return <Navigate to="/login" replace state={state} />
  }

  return <Outlet />
}

function CenteredMessage({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-3 text-muted-foreground">
      {children}
    </main>
  )
}
