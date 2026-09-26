import { useMemo } from 'react'
import {
  Activity,
  Boxes,
  BrainCircuit,
  Database,
  Search,
  Server,
  ShieldCheck,
  Siren,
  type LucideIcon,
} from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { StatusIndicator } from '@/components/StatusIndicator'
import { ErrorState } from '@/components/ErrorState'
import { RefreshControl } from '@/components/RefreshControl'
import { SkeletonCard } from '@/components/LoadingSkeleton'
import { getDashboardSummary, getHealth, getIntegrity } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { useSettings } from '@/hooks/useSettings'
import { formatNumber, humanize } from '@/utils/format'

type State = 'online' | 'warning' | 'offline' | 'unknown'

interface ServiceRow {
  name: string
  icon: LucideIcon
  state: State
  label: string
  detail: string
}

const STATE_LABEL: Record<State, string> = {
  online: 'Online',
  warning: 'Warning',
  offline: 'Unavailable',
  unknown: 'Unknown',
}

export function StatusPage() {
  const { refreshIntervalMs } = useSettings()
  const opts = { pollMs: refreshIntervalMs }
  const health = useApi((s) => getHealth(s), [], opts)
  const integrity = useApi((s) => getIntegrity(s), [], opts)
  const dash = useApi((s) => getDashboardSummary(s), [], opts)

  const refetchAll = () => {
    health.refetch()
    integrity.refetch()
    dash.refetch()
  }
  const caps = dash.data?.capabilities

  const services = useMemo<ServiceRow[]>(() => {
    // Backend API — reachable if /health responded without a transport error.
    const apiOk = Boolean(health.data)
    const api: ServiceRow = {
      name: 'Backend API',
      icon: Server,
      state: apiOk ? 'online' : health.error ? 'offline' : 'unknown',
      label: apiOk ? STATE_LABEL.online : health.error ? STATE_LABEL.offline : STATE_LABEL.unknown,
      detail: apiOk
        ? humanize(String(health.data?.status ?? 'ok'))
        : health.error ?? 'Awaiting response…',
    }

    // Database — reachable if the summary query returned.
    const dbOk = Boolean(dash.data)
    const db: ServiceRow = {
      name: 'Event Database',
      icon: Database,
      state: dbOk ? 'online' : dash.error ? 'offline' : 'unknown',
      label: dbOk ? STATE_LABEL.online : dash.error ? STATE_LABEL.offline : STATE_LABEL.unknown,
      detail: dbOk
        ? `${formatNumber(dash.data?.total_events ?? 0)} events stored`
        : dash.error ?? 'Awaiting response…',
    }

    // Evidence integrity — map the hash-chain status to a service state.
    const st = integrity.data?.status?.toUpperCase()
    const integrityState: State =
      st === 'VERIFIED' ? 'online' : st === 'TAMPERED' ? 'offline' : st ? 'warning' : 'unknown'
    const integ: ServiceRow = {
      name: 'Evidence Integrity',
      icon: ShieldCheck,
      state: integrity.error ? 'offline' : integrityState,
      label: integrity.error
        ? STATE_LABEL.offline
        : st
          ? humanize(st)
          : STATE_LABEL.unknown,
      detail: integrity.error
        ? integrity.error
        : integrity.data
          ? `${formatNumber(integrity.data.hashed_events)} hashed · ${formatNumber(integrity.data.legacy_events)} legacy`
          : 'Awaiting response…',
    }

    // Capability-derived engines (deterministic availability flags).
    const cap = (name: string, icon: LucideIcon, available?: boolean, note?: string): ServiceRow => ({
      name,
      icon,
      state: available == null ? 'unknown' : available ? 'online' : 'warning',
      label: available == null ? STATE_LABEL.unknown : available ? 'Available' : 'Unavailable',
      detail: note ?? (available == null ? 'Awaiting response…' : available ? 'Ready' : 'Not currently available'),
    })

    const ai = cap(
      'AI Investigation (Ollama)',
      Search,
      caps?.investigation_available,
      caps?.investigation_available == null
        ? 'Awaiting response…'
        : caps.investigation_available
          ? 'Investigation engine ready. Live model state is confirmed per query.'
          : 'Investigation engine unavailable.',
    )
    const correlation = cap('Correlation Engine', Siren, caps?.correlation_available)
    const behavior = cap('Behavior Analysis', BrainCircuit, caps?.behavior_available)

    // Collectors — presence inferred from collected evidence.
    const sourceCount = Object.keys(dash.data?.events_by_source ?? {}).length
    const collectors: ServiceRow = {
      name: 'Collectors',
      icon: Boxes,
      state: dash.error ? 'offline' : sourceCount > 0 ? 'online' : 'unknown',
      label: dash.error ? STATE_LABEL.offline : sourceCount > 0 ? 'Reporting' : STATE_LABEL.unknown,
      detail: dash.error
        ? dash.error
        : sourceCount > 0
          ? `${sourceCount} source${sourceCount === 1 ? '' : 's'} reporting evidence`
          : 'No collected sources detected',
    }

    return [api, db, integ, ai, correlation, behavior, collectors]
  }, [health.data, health.error, dash.data, dash.error, integrity.data, integrity.error, caps])
  const booting =
    !health.data && !integrity.data && !dash.data &&
    !health.error && !integrity.error && !dash.error
  const anyRefreshing = health.refreshing || integrity.refreshing || dash.refreshing
  const lastUpdated =
    Math.max(health.lastUpdated ?? 0, integrity.lastUpdated ?? 0, dash.lastUpdated ?? 0) || null

  const offlineCount = services.filter((s) => s.state === 'offline').length
  const warnCount = services.filter((s) => s.state === 'warning').length
  const overall: State = offlineCount ? 'offline' : warnCount ? 'warning' : 'online'
  const overallLabel = offlineCount
    ? 'Service disruption detected'
    : warnCount
      ? 'Operational with warnings'
      : 'All systems operational'

  return (
    <div className="space-y-5">
      <PageHeader
        title="System Status"
        description="Live health of the ForensiX services and evidence pipeline."
        icon={<Activity className="h-5 w-5" />}
        actions={
          <RefreshControl onRefresh={refetchAll} refreshing={anyRefreshing} lastUpdated={lastUpdated} />
        }
      />

      {booting ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <SkeletonCard key={i} className="h-16" />
          ))}
        </div>
      ) : (
        <>
          {!health.data && health.error && (
            <ErrorState
              compact
              message="Unable to reach the ForensiX backend. Service states below reflect the last known result."
              onRetry={refetchAll}
            />
          )}

          <div className="fx-card flex items-center justify-between gap-4 p-5">
            <div>
              <div className="text-xs uppercase tracking-wide text-fg-faint">Overall</div>
              <div className="mt-1 text-lg font-semibold text-fg">{overallLabel}</div>
            </div>
            <StatusIndicator state={overall} label={STATE_LABEL[overall]} pulse />
          </div>

          <div className="space-y-3">
            {services.map((s) => {
              const Icon = s.icon
              return (
                <div key={s.name} className="fx-card flex items-center justify-between gap-4 p-4">
                  <div className="flex items-start gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-surface2 text-brand">
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-fg">{s.name}</div>
                      <div className="mt-0.5 text-xs text-fg-muted">{s.detail}</div>
                    </div>
                  </div>
                  <StatusIndicator state={s.state} label={s.label} pulse />
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
