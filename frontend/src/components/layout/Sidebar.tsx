import { BookOpenCheck, LayoutDashboard, ScrollText, ShieldAlert, Upload, Users } from 'lucide-react'
import { NavLink, useSearchParams } from 'react-router'
import { isDataPage } from '@/lib/navigation'
import { cn } from '@/lib/utils'

const ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/investigations', label: 'Investigations', icon: ShieldAlert },
  { to: '/users', label: 'Users', icon: Users },
  { to: '/logs', label: 'Logs', icon: ScrollText },
  { to: '/uploads', label: 'Upload Logs', icon: Upload },
  { to: '/rules', label: 'Detection Rules', icon: BookOpenCheck },
]

/** Dark navigation panel (in both themes). Data-page links keep the selected upload (?upload=). */
export default function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const [params] = useSearchParams()
  const upload = params.get('upload')
  return (
    <div className="flex h-full flex-col bg-nav-bg text-nav-fg">
      <div className="px-5 py-5 text-lg font-bold tracking-tight">
        SOC <span className="text-nav-accent">Analyzer</span>
      </div>
      <nav aria-label="Main" className="flex flex-col gap-1 px-2">
        {ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={isDataPage(to) && upload ? `${to}?upload=${upload}` : to}
            onClick={onNavigate}
            // NavLink sets aria-current="page" on the active item for screen readers.
            className={({ isActive }) => cn(
              'flex items-center gap-3 rounded-md border-l-2 px-3 py-2.5 text-sm transition-colors',
              isActive
                ? 'border-nav-accent bg-nav-active-bg font-medium text-nav-fg'
                : 'border-transparent text-nav-muted hover:bg-nav-active-bg/60 hover:text-nav-fg',
            )}
          >
            <Icon className="size-4 shrink-0" aria-hidden />
            {label}
          </NavLink>
        ))}
      </nav>
    </div>
  )
}
