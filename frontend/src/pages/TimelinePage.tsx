import { useMemo, useState } from 'react'
import { GitBranch } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Timeline } from '@/components/Timeline'
import { EventDetailsPanel } from '@/components/EventDetailsPanel'
import { FilterBar, SelectFilter } from '@/components/FilterBar'
import { Pagination } from '@/components/Pagination'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonText } from '@/components/LoadingSkeleton'
import { getDashboardSummary, getTimeline } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import type { EventResponse } from '@/types'
import { humanize } from '@/utils/format'

const SEVERITIES = ['INFO', 'LOW', 'WARNING', 'MEDIUM', 'ERROR', 'HIGH', 'CRITICAL']
const PAGE_SIZE = 40

export function TimelinePage() {
  const { refreshIntervalMs } = useSettings()
  const [selected, setSelected] = useState<EventResponse | null>(null)
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [offset, setOffset] = useState(0)

  const query = useMemo(
    () => ({
      limit: PAGE_SIZE,
      offset,
      severity: severity || undefined,
      source: source || undefined,
    }),
    [offset, severity, source],
  )

  const { data, loading, error, refetch, refreshing, lastUpdated } = useApi(
    (signal) => getTimeline(query, signal),
    [JSON.stringify(query)],
    { pollMs: refreshIntervalMs },
  )

  const summary = useApi((signal) => getDashboardSummary(signal), [])
  const sourceOptions = useMemo(() => {
    const keys = Object.keys(summary.data?.events_by_source ?? {})
    return [{ value: '', label: 'All sources' }, ...keys.map((k) => ({ value: k, label: k }))]
  }, [summary.data])

  const onFilter = <T,>(setter: (v: T) => void) => (v: T) => {
    setter(v)
    setOffset(0)
  }

  const events = data?.events ?? []
  const hasFilters = Boolean(severity || source)

  return (
    <div className="space-y-5">
      <PageHeader
        title="Forensic Timeline"
        description="A chronological reconstruction of endpoint activity."
        icon={<GitBranch className="h-5 w-5" />}
        actions={
          <RefreshControl onRefresh={refetch} refreshing={refreshing} lastUpdated={lastUpdated} />
        }
      />

      <FilterBar>
        <SelectFilter
          label="Severity"
          value={severity}
          onChange={onFilter(setSeverity)}
          options={[
            { value: '', label: 'All severities' },
            ...SEVERITIES.map((s) => ({ value: s, label: humanize(s) })),
          ]}
        />
        <SelectFilter
          label="Source"
          value={source}
          onChange={onFilter(setSource)}
          options={sourceOptions}
        />
      </FilterBar>

      {error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading ? (
        <div className="fx-card p-6">
          <SkeletonText lines={10} />
        </div>
      ) : events.length === 0 ? (
        <EmptyState
          title={hasFilters ? 'No matching events' : 'No timeline data'}
          message={
            hasFilters
              ? 'Try adjusting or clearing your filters.'
              : 'Once events are collected, the timeline will populate here.'
          }
        />
      ) : (
        <div className="fx-card p-5 sm:p-6">
          <Timeline events={events} onSelect={setSelected} />
          <div className="mt-6 border-t border-line-soft pt-4">
            <Pagination
              total={data?.total ?? 0}
              limit={PAGE_SIZE}
              offset={offset}
              onChange={setOffset}
              noun="events"
            />
          </div>
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
