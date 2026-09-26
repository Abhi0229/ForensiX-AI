import { useState } from 'react'
import { Info, Siren } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { IncidentCard } from '@/components/IncidentCard'
import { EventDetailsPanel } from '@/components/EventDetailsPanel'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonCard } from '@/components/LoadingSkeleton'
import { getIncidents } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import type { EventResponse } from '@/types'

export function IncidentsPage() {
  const { refreshIntervalMs } = useSettings()
  const [selected, setSelected] = useState<EventResponse | null>(null)

  const { data, loading, error, refetch, refreshing, lastUpdated } = useApi(
    (signal) => getIncidents(signal),
    [],
    { pollMs: refreshIntervalMs },
  )

  const incidents = data?.candidate_incidents ?? []

  return (
    <div className="space-y-5">
      <PageHeader
        title="Candidate Incidents"
        description="Correlated clusters of events that may warrant closer review."
        icon={<Siren className="h-5 w-5" />}
        actions={
          <RefreshControl onRefresh={refetch} refreshing={refreshing} lastUpdated={lastUpdated} />
        }
      />

      {/* Terminology clarification — these are candidates, not confirmed attacks. */}
      <div className="flex items-start gap-2.5 rounded-card border border-brand/25 bg-brand/5 p-3.5">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-brand" />
        <p className="text-sm text-fg-muted">
          {data?.note ||
            'These are candidate incidents produced by automated correlation. They are leads for investigation, not confirmed attacks.'}
        </p>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <SkeletonCard key={i} className="h-40" />
          ))}
        </div>
      ) : incidents.length === 0 ? (
        <EmptyState
          icon={Siren}
          title="No candidate incidents"
          message="Correlation has not grouped any events into candidate incidents yet."
        />
      ) : (
        <div className="space-y-4">
          {incidents.map((incident) => (
            <IncidentCard
              key={incident.incident_id}
              incident={incident}
              onSelectEvent={setSelected}
            />
          ))}
        </div>
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
