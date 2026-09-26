import { ShieldCheck } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { IntegrityStatus } from '@/components/IntegrityStatus'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonCard } from '@/components/LoadingSkeleton'
import { getIntegrity } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'

export function IntegrityPage() {
  const { refreshIntervalMs } = useSettings()
  const { data, loading, error, refetch, refreshing, lastUpdated } = useApi(
    (signal) => getIntegrity(signal),
    [],
    { pollMs: refreshIntervalMs },
  )

  return (
    <div className="space-y-5">
      <PageHeader
        title="Evidence Integrity"
        description="Tamper-evidence for the collected event store."
        icon={<ShieldCheck className="h-5 w-5" />}
        actions={
          <RefreshControl onRefresh={refetch} refreshing={refreshing} lastUpdated={lastUpdated} />
        }
      />

      {error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading ? (
        <SkeletonCard className="h-64" />
      ) : data ? (
        <div className="grid gap-5 lg:grid-cols-3">
          <IntegrityStatus integrity={data} detailed className="lg:col-span-2" />

          <div className="fx-card p-5">
            <h3 className="text-sm font-semibold text-fg">How this works</h3>
            <div className="mt-3 space-y-3 text-sm leading-relaxed text-fg-muted">
              <p>
                Each collected event is hashed together with the hash of the
                previous event, forming a chained sequence.
              </p>
              <p>
                Altering any event would change its hash and break every link
                that follows, making tampering detectable.
              </p>
              <ul className="space-y-2 pt-1">
                <li className="flex gap-2">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-status-ok" />
                  <span><strong className="text-fg">Verified</strong> — all hashed links are intact.</span>
                </li>
                <li className="flex gap-2">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-status-legacy" />
                  <span><strong className="text-fg">Legacy</strong> — pre-dates hashing; cannot be verified.</span>
                </li>
                <li className="flex gap-2">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-status-danger" />
                  <span><strong className="text-fg">Tampered</strong> — a broken link was detected.</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
