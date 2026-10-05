import { lazy, Suspense, type ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router'
import AppLayout from '@/components/AppLayout'
import RequireAuth from '@/components/RequireAuth'
import InvestigationDetailPage from '@/pages/InvestigationDetailPage'
import InvestigationsPage from '@/pages/InvestigationsPage'
import LoginPage from '@/pages/LoginPage'
import LogsPage from '@/pages/LogsPage'
import NotFoundPage from '@/pages/NotFoundPage'
import RulesPage from '@/pages/RulesPage'
import UploadDetailPage from '@/pages/UploadDetailPage'
import UploadsPage from '@/pages/UploadsPage'
import UserProfilePage from '@/pages/UserProfilePage'
import UsersPage from '@/pages/UsersPage'

// Code splitting: the dashboard (with the charting library) is only downloaded when opened,
// so login and the other pages stay small.
const DashboardPage = lazy(() => import('@/pages/DashboardPage'))

function Lazy({ children }: { children: ReactNode }) {
  return <Suspense fallback={<p className="p-4 text-sm text-muted-foreground">Loading…</p>}>{children}</Suspense>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Layout routes: RequireAuth decides WHETHER to show; AppLayout decides HOW (sidebar + top bar). */}
      <Route element={<RequireAuth />}>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Lazy><DashboardPage /></Lazy>} />
          <Route path="/investigations" element={<InvestigationsPage />} />
          <Route path="/investigations/:caseId" element={<InvestigationDetailPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/uploads" element={<UploadsPage />} />
          <Route path="/uploads/:uploadId" element={<UploadDetailPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/users/:username" element={<UserProfilePage />} />
        </Route>
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
