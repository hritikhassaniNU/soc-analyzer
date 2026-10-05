import { LogOut, Menu, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router'
import { useLogout, useMe } from '@/api/auth'
import Sidebar from '@/components/layout/Sidebar'
import { Button } from '@/components/ui/button'

/** Shell for every logged-in page: sidebar navigation + a top bar + the current page. */
export default function AppLayout() {
  const me = useMe()
  const logout = useLogout()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  // The phone menu is open only on the page it was opened on, so any navigation closes it
  // (links, Back/Forward) without an effect that sets state after every route change.
  const [openOn, setOpenOn] = useState<string | null>(null)
  const menuOpen = openOn === pathname
  const setMenuOpen = (open: boolean) => setOpenOn(open ? pathname : null)

  useEffect(() => {
    if (!menuOpen) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpenOn(null) // setOpenOn is stable
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [menuOpen])

  function handleLogout() {
    // onSettled: leave even if the request failed; the local cache is cleared either way.
    logout.mutate(undefined, { onSettled: () => navigate('/login', { replace: true }) })
  }

  return (
    <div className="flex min-h-svh">
      {/* Wide screens: a fixed sidebar. */}
      <aside className="sticky top-0 hidden h-svh w-60 shrink-0 md:block">
        <Sidebar />
      </aside>

      {/* Phone width: the same sidebar slides over the page from a menu button. */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <button type="button" aria-label="Close menu" className="absolute inset-0 bg-black/50" onClick={() => setMenuOpen(false)} />
          <aside id="mobile-nav" className="absolute inset-y-0 left-0 w-64 shadow-xl">
            <Sidebar onNavigate={() => setMenuOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b bg-background/95 backdrop-blur">
          <div className="flex h-14 items-center gap-3 px-4">
            <Button
              variant="ghost"
              size="icon-sm"
              className="md:hidden"
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={menuOpen}
              aria-controls="mobile-nav"
              onClick={() => setMenuOpen(!menuOpen)}
            >
              {menuOpen ? <X /> : <Menu />}
            </Button>
            <div className="flex-1" />
            <span className="hidden text-sm text-muted-foreground sm:inline">{me.data?.username}</span>
            <Button variant="outline" size="sm" onClick={handleLogout} disabled={logout.isPending}>
              <LogOut />
              Logout
            </Button>
          </div>
        </header>
        <Outlet />
      </div>
    </div>
  )
}
