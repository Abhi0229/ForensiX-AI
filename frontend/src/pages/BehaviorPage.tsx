import { AlertCircle, BrainCircuit } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { AnomalyCard } from '@/components/AnomalyCard'
import { Badge } from '@/components/Badge'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonCard } from '@/components/LoadingSkeleton'
import { getBehaviorAnomalies } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import { cn } from '@/utils/cn'
import { formatNumber, humanize } from '@/utils/format'
import { classificationTone } from '@/utils/severity'

const CLASS_ORDER = ['ANOMALOUS', 'SUSPICIOUS', 'NORMAL', 'INSUFFICIENT_HISTORY']

export function BehaviorPage() {
  const { refreshIntervalMs } = useSettings()
  const { data, loading, error, refetch, refreshing, lastUpdated } = useApi(
    (signal) => getBehaviorAnomalies({ limit: 100 }, signal),
    [],
    { pollMs: refreshIntervalMs },
  )

  const anomalies = data?.anomalies ?? []
  const counts = data?.counts

  return (
    <div className="space-y-5">
      <PageHeader
        title="Behavior Analysis"
        description="Statistical deviations from the learned activity baseline."
        icon={<BrainCircuit className="h-5 w-5" />}
        actions={
          <RefreshControl onRefresh={refetch} refreshing={refreshing} lastUpdated={lastUpdated} />
        }
      />

      {/* Disclaimer — an anomaly is not a confirmed threat. */}
      <div className="flex items-start gap-2.5 rounded-card border border-violet/25 bg-violet/5 p-3.5">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-violet" />
        <p className="text-sm text-fg-muted">
          {data?.disclaimer ||
            'Anomaly scores measure how far an event deviates from normal patterns. They are not probabilities of malicious activity — an anomaly is not a confirmed threat.'}
        </p>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading ? (
        <div className="grid gap-3 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonCard key={i} className="h-48" />
          ))}
        </div>
      ) : (
        <>
          {/* Classification breakdown + baseline status */}
          <div className="flex flex-col gap-4 sm:flex-row sm:items-stretch">
            <div className="grid flex-1 grid-cols-2 gap-3 sm:grid-cols-4">
              {CLASS_ORDER.map((key) => {
                const tone = classificationTone(key)
                return (
                  <div key={key} className="fx-card p-4">
                    <div className="text-2xl font-semibold tabular-nums text-fg">
                      {formatNumber(counts?.[key] ?? 0)}
                    </div>
                    <div className={cn('mt-1 text-xs font-medium', tone.text)}>
                      {humanize(key)}
                    </div>
                  </div>
                )
              })}
            </div>
            <div className="fx-card flex flex-col justify-center p-4 sm:w-56">
              <div className="text-xs uppercase tracking-wide text-fg-faint">Baseline status</div>
              <div className="mt-2">
                <Badge className="text-fg bg-surface3 border-line">
                  {data?.baseline_status ? humanize(data.baseline_status) : 'Unknown'}
                </Badge>
              </div>
              <div className="mt-2 text-xs text-fg-muted">
                {formatNumber(data?.total_evaluated ?? 0)} events evaluated
              </div>
            </div>
          </div>

          {anomalies.length === 0 ? (
            <EmptyState
              icon={BrainCircuit}
              title="No anomalies detected"
              message="No events currently deviate meaningfully from the learned baseline."
            />
          ) : (
            <div className="grid gap-3 lg:grid-cols-2">
              {anomalies.map((a, i) => (
                <AnomalyCard key={a.event?.event_id ?? i} anomaly={a} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
