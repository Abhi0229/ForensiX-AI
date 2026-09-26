import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  BrainCircuit,
  Clock,
  LayoutDashboard,
  ListTree,
  ShieldCheck,
  Siren,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/StatCard'
import { ChartCard } from '@/components/ChartCard'
import { EventTable } from '@/components/EventTable'
import { EventDetailsPanel } from '@/components/EventDetailsPanel'
import { IntegrityStatus } from '@/components/IntegrityStatus'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonCard, SkeletonTable } from '@/components/LoadingSkeleton'
import { SeverityDonut } from '@/components/charts/SeverityDonut'
import { SourceBar } from '@/components/charts/SourceBar'
import { ActivityArea } from '@/components/charts/ActivityArea'
import { getDashboardSummary, getTimeline } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import type { EventResponse } from '@/types'
import { formatNumber, formatRelative, humanize, NOT_AVAILABLE } from '@/utils/format'

export function DashboardPage() {
  const navigate = useNavigate()
  const { refreshIntervalMs } = useSettings()
  const [selected, setSelected] = useState<EventResponse | null>(null)

  const summary = useApi((signal) => getDashboardSummary(signal), [], {
    pollMs: refreshIntervalMs,
  })
  const timeline = useApi((signal) => getTimeline({ limit: 200 }, signal), [], {
    pollMs: refreshIntervalMs,
  })

  const data = summary.data
  const integrityStatus = data?.integrity?.status
    ? humanize(data.integrity.status)
    : NOT_AVAILABLE

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Overview of collected evidence and current investigative signals."
        icon={<LayoutDashboard className="h-5 w-5" />}
        actions={
          <RefreshControl
            onRefresh={() => {
              summary.refetch()
              timeline.refetch()
            }}
            refreshing={summary.refreshing}
            lastUpdated={summary.lastUpdated}
          />
        }
      />

      {summary.error ? (
        <ErrorState message={summary.error} onRetry={summary.refetch} />
      ) : summary.loading ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            {Array.from({ length: 5 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
          <SkeletonTable rows={6} />
        </>
      ) : data ? (
        <>
          {/* KPI row */}
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <StatCard
              label="Total Events"
              value={formatNumber(data.total_events)}
              icon={ListTree}
              accent="brand"
              hint="Collected across all sources"
              onClick={() => navigate('/events')}
            />
            <StatCard
              label="Candidate Incidents"
              value={formatNumber(data.candidate_incident_count)}
              icon={Siren}
              accent={data.candidate_incident_count > 0 ? 'warn' : 'neutral'}
              hint="Correlated event clusters"
              onClick={() => navigate('/incidents')}
            />
            <StatCard
              label="Behavioral Anomalies"
              value={formatNumber(data.behavioral_anomaly_count)}
              icon={BrainCircuit}
              accent={data.behavioral_anomaly_count > 0 ? 'violet' : 'neutral'}
              hint="Deviations from baseline"
              onClick={() => navigate('/behavior')}
            />
            <StatCard
              label="Integrity"
              value={integrityStatus}
              icon={ShieldCheck}
              accent={data.integrity?.valid ? 'ok' : 'warn'}
              hint="Hash-chain verification"
              onClick={() => navigate('/integrity')}
            />
            <StatCard
              label="Latest Event"
              value={
                data.latest_event_timestamp
                  ? formatRelative(data.latest_event_timestamp)
                  : NOT_AVAILABLE
              }
              icon={Clock}
              accent="cyan"
              hint="Most recent activity"
            />
          </div>

          {/* Charts */}
          <div className="grid gap-4 lg:grid-cols-2">
            <ChartCard title="Events by severity" description="Distribution across severity levels">
              <SeverityDonut data={data.events_by_severity} />
            </ChartCard>
            <ChartCard title="Events by source" description="Top contributing collectors">
              <SourceBar data={data.events_by_source} />
            </ChartCard>
          </div>

          <ChartCard
            title="Event activity over time"
            description="Volume of events derived from recent timeline data"
          >
            {timeline.loading ? (
              <div className="h-[260px] fx-skeleton" />
            ) : timeline.error ? (
              <ErrorState compact message={timeline.error} onRetry={timeline.refetch} />
            ) : (
              <ActivityArea events={timeline.data?.events ?? []} />
            )}
          </ChartCard>

          {/* Integrity + recent events */}
          <div className="grid gap-4 lg:grid-cols-3">
            {data.integrity && (
              <IntegrityStatus integrity={data.integrity} detailed className="lg:col-span-1" />
            )}
            <div className="lg:col-span-2">
              <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-fg">
                <Activity className="h-4 w-4 text-brand" /> Recent events
              </h2>
              {data.recent_events?.length > 0 ? (
                <EventTable
                  events={data.recent_events}
                  onSelect={setSelected}
                  selectedId={selected?.id}
                />
              ) : (
                <EmptyState
                  title="No events yet"
                  message="Once collectors ingest data, the most recent events will appear here."
                />
              )}
            </div>
          </div>
        </>
      ) : (
        <EmptyState title="No data available" />
      )}

      <EventDetailsPanel
        event={selected}
        open={selected !== null}
        onClose={() => setSelected(null)}
        onSelectRelated={setSelected}
      />
    </div>
  )
}
