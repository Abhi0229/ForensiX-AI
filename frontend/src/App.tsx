import { Routes, Route } from 'react-router-dom'
import { AppLayout } from '@/layouts/AppLayout'
import { DashboardPage } from '@/pages/DashboardPage'
import { InvestigatePage } from '@/pages/InvestigatePage'
import { EventsPage } from '@/pages/EventsPage'
import { TimelinePage } from '@/pages/TimelinePage'
import { IncidentsPage } from '@/pages/IncidentsPage'
import { BehaviorPage } from '@/pages/BehaviorPage'
import { IntegrityPage } from '@/pages/IntegrityPage'
import { ReportsPage } from '@/pages/ReportsPage'
import { CollectorsPage } from '@/pages/CollectorsPage'
import { StatusPage } from '@/pages/StatusPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

/** Application routes. All pages render inside the persistent AppLayout shell. */
export function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="investigate" element={<InvestigatePage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="timeline" element={<TimelinePage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="behavior" element={<BehaviorPage />} />
        <Route path="integrity" element={<IntegrityPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="collectors" element={<CollectorsPage />} />
        <Route path="status" element={<StatusPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
