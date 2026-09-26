import { useMemo, useState } from 'react'
import { ListTree } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { EventTable } from '@/components/EventTable'
import { EventDetailsPanel } from '@/components/EventDetailsPanel'
import { FilterBar, SearchInput, SelectFilter } from '@/components/FilterBar'
import { Pagination } from '@/components/Pagination'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonTable } from '@/components/LoadingSkeleton'
import { getDashboardSummary, getEvents } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import type { EventResponse } from '@/types'
import { humanize } from '@/utils/format'

const SEVERITIES = ['INFO', 'LOW', 'WARNING', 'MEDIUM', 'ERROR', 'HIGH', 'CRITICAL', 'AUDIT_SUCCESS', 'AUDIT_FAILURE']
const PAGE_SIZE = 25

export function EventsPage() {
  const { refreshIntervalMs } = useSettings()
  const [selected, setSelected] = useState<EventResponse | null>(null)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [offset, setOffset] = useState(0)

  const query = useMemo(
    () => ({
      limit: PAGE_SIZE,
      offset,
      search: search.trim() || undefined,
      severity: severity || undefined,
      source: source || undefined,
    }),
    [offset, search, severity, source],
  )

  const { data, loading, error, refetch, refreshing, lastUpdated } = useApi(
    (signal) => getEvents(query, signal),
    [JSON.stringify(query)],
    { pollMs: refreshIntervalMs },
  )

  // Source options for the filter dropdown (from the dashboard summary).
  const summary = useApi((signal) => getDashboardSummary(signal), [])
  const sourceOptions = useMemo(() => {
    const keys = Object.keys(summary.data?.events_by_source ?? {})
    return [{ value: '', label: 'All sources' }, ...keys.map((k) => ({ value: k, label: k }))]
  }, [summary.data])

  const resetOffset = <T,>(setter: (v: T) => void) => (v: T) => {
    setter(v)
    setOffset(0)
  }

  const events = data?.events ?? []
  const hasFilters = Boolean(search || severity || source)

  return (
    <div className="space-y-5">
      <PageHeader
        title="Event Explorer"
        description="Browse and filter every event collected from this endpoint."
        icon={<ListTree className="h-5 w-5" />}
        actions={
          <RefreshControl
            onRefresh={refetch}
            refreshing={refreshing}
            lastUpdated={lastUpdated}
          />
        }
      />

      <FilterBar>
        <SearchInput
          value={search}
          onChange={resetOffset(setSearch)}
          placeholder="Search descriptions, types, users…"
        />
        <SelectFilter
          label="Severity"
          value={severity}
          onChange={resetOffset(setSeverity)}
          options={[
            { value: '', label: 'All severities' },
            ...SEVERITIES.map((s) => ({ value: s, label: humanize(s) })),
          ]}
        />
        <SelectFilter
          label="Source"
          value={source}
          onChange={resetOffset(setSource)}
          options={sourceOptions}
        />
      </FilterBar>

      {error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading ? (
        <SkeletonTable rows={10} />
      ) : events.length === 0 ? (
        <EmptyState
          title={hasFilters ? 'No matching events' : 'No events recorded'}
          message={
            hasFilters
              ? 'Try adjusting or clearing your filters to see more results.'
              : 'Once collectors ingest data, events will appear here.'
          }
        />
      ) : (
        <>
          <EventTable events={events} onSelect={setSelected} selectedId={selected?.id} />
          <Pagination
            total={data?.total ?? 0}
            limit={PAGE_SIZE}
            offset={offset}
            onChange={setOffset}
            noun="events"
          />
        </>
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
