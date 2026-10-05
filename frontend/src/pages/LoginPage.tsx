import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { useLogin, useMe } from '@/api/auth'
import type { LoginRedirectState } from '@/components/RequireAuth'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { HttpError } from '@/lib/queryClient'

export default function LoginPage() {
  const me = useMe()
  const login = useLogin()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as LoginRedirectState | null)?.from ?? '/'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  // Already logged in: never show the login form.
  if (me.data) {
    return <Navigate to={from} replace />
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault() // stay in the SPA: no full-page form post
    login.mutate(
      { username, password },
      {
        onSuccess: () => navigate(from, { replace: true }),
        onError: () => setPassword(''), // keep the username, clear the password
      },
    )
  }

  const errorMessage = login.isError
    ? login.error instanceof HttpError && login.error.status === 401
      ? 'Invalid username or password'
      : "Can't reach the server. Try again."
    : null

  return (
    <main className="flex min-h-svh items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="page-title">SOC Analyzer</CardTitle>
          <CardDescription>Sign in to analyze proxy logs.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                autoComplete="username" // lets password managers fill and save correctly
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {errorMessage && (
              // role="alert": screen readers announce the error when it appears
              <p role="alert" className="text-sm text-destructive">
                {errorMessage}
              </p>
            )}
            {/* Disabled while waiting: no double submits during the ~0.2 s password check */}
            <Button type="submit" disabled={login.isPending}>
              {login.isPending ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
