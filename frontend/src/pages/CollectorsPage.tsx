import { useMemo } from 'react'
import {
  Boxes,
  Chrome,
  FileText,
  Info,
  Monitor,
  ShieldCheck,
  Usb,
  type LucideIcon,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Badge } from '@/components/Badge'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonCard } from '@/components/LoadingSkeleton'
import { getDashboardSummary } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import { formatNumber } from '@/utils/format'

interface CollectorDef {
  key: string
  name: string
  description: string
  keywords: string[]
  icon: LucideIcon
}

/** Known Windows collectors. Presence is inferred from collected evidence only. */
const COLLECTORS: CollectorDef[] = [
  { key: 'windows', name: 'Windows Event Log', description: 'Security, System and Application channels.', keywords: ['windows', 'event', 'eventlog', 'security', 'system'], icon: Monitor },
  { key: 'defender', name: 'Windows Defender', description: 'Antimalware detections and scan results.', keywords: ['defender', 'antivirus', 'threat'], icon: ShieldCheck },
  { key: 'file', name: 'File System', description: 'File create, modify and delete activity.', keywords: ['file', 'filesystem', 'ntfs'], icon: FileText },
  { key: 'usb', name: 'USB / Removable Media', description: 'Removable device insertions and usage.', keywords: ['usb', 'removable'], icon: Usb },
  { key: 'browser', name: 'Browser History', description: 'Visited URLs and download history.', keywords: ['browser', 'chrome', 'edge', 'firefox'], icon: Chrome },
]

export function CollectorsPage() {
  const { refreshIntervalMs } = useSettings()
  const { data, loading, error, refetch, refreshing, lastUpdated } = useApi(
    (signal) => getDashboardSummary(signal),
    [],
    { pollMs: refreshIntervalMs },
  )
  const bySource = data?.events_by_source

  // Attribute each collected source to a collector, then find any leftovers.
  const { rows, others } = useMemo(() => {
    const entries = Object.entries(bySource ?? {})
    const claimed = new Set<string>()
    const rows = COLLECTORS.map((c) => {
      let count = 0
      for (const [src, n] of entries) {
        if (c.keywords.some((k) => src.toLowerCase().includes(k))) {
          count += n
          claimed.add(src)
        }
      }
      return { ...c, count }
    })
    const others = entries.filter(([src]) => !claimed.has(src))
    return { rows, others }
  }, [bySource])

  return (
    <div className="space-y-5">
      <PageHeader
        title="Collectors"
        description="Data sources feeding the ForensiX evidence store."
        icon={<Boxes className="h-5 w-5" />}
        actions={
          <RefreshControl onRefresh={refetch} refreshing={refreshing} lastUpdated={lastUpdated} />
        }
      />

      {/* Honest framing — the API does not expose live agent heartbeats. */}
      <div className="flex items-start gap-2.5 rounded-card border border-brand/25 bg-brand/5 p-3.5">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-brand" />
        <p className="text-sm text-fg-muted">
          The backend does not expose live collector run-state. The status below
          reflects whether evidence has been collected from each source — not a
          real-time agent heartbeat.
        </p>
      </div>
      {error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : loading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <SkeletonCard key={i} className="h-36" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {rows.map((c) => {
            const Icon = c.icon
            const hasData = c.count > 0
            return (
              <div key={c.key} className="fx-card flex flex-col p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-surface2 text-brand">
                    <Icon className="h-5 w-5" />
                  </div>
                  <Badge
                    className={
                      hasData
                        ? 'text-status-ok bg-status-ok/10 border-status-ok/30'
                        : 'text-fg-muted bg-surface3/60 border-line'
                    }
                    dotClassName={hasData ? 'bg-status-ok' : 'bg-fg-faint'}
                  >
                    {hasData ? 'Evidence collected' : 'No events recorded'}
                  </Badge>
                </div>
                <h3 className="mt-4 text-sm font-semibold text-fg">{c.name}</h3>
                <p className="mt-1 text-xs leading-relaxed text-fg-muted">{c.description}</p>
                <div className="mt-4 border-t border-line-soft pt-3">
                  <span className="text-lg font-semibold tabular-nums text-fg">
                    {formatNumber(c.count)}
                  </span>
                  <span className="ml-1.5 text-xs text-fg-faint">events collected</span>
                </div>
              </div>
            )
          })}

          {others.map(([src, n]) => (
            <div key={src} className="fx-card flex flex-col p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-surface2 text-fg-muted">
                  <Boxes className="h-5 w-5" />
                </div>
                <Badge className="text-status-ok bg-status-ok/10 border-status-ok/30" dotClassName="bg-status-ok">
                  Evidence collected
                </Badge>
              </div>
              <h3 className="mt-4 text-sm font-semibold text-fg">{src}</h3>
              <p className="mt-1 text-xs leading-relaxed text-fg-muted">
                Additional source reported by the backend.
              </p>
              <div className="mt-4 border-t border-line-soft pt-3">
                <span className="text-lg font-semibold tabular-nums text-fg">{formatNumber(n)}</span>
                <span className="ml-1.5 text-xs text-fg-faint">events collected</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
