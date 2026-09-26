import { useState } from 'react'
import { ChevronDown, Clock, GitBranch, Layers } from 'lucide-react'
import { Badge } from './Badge'
import { SeverityBadge } from './SeverityBadge'
import type { EventResponse, IncidentResponse } from '@/types'
import { cn } from '@/utils/cn'
import { formatDateTime, humanize, NOT_AVAILABLE } from '@/utils/format'
import { priorityTone } from '@/utils/severity'

interface IncidentCardProps {
  incident: IncidentResponse
  onSelectEvent?: (event: EventResponse) => void
  className?: string
}

/**
 * A candidate incident card. Terminology is deliberately "Candidate Incident"
 * — these are correlated event clusters, not confirmed attacks. The confidence
 * score reflects correlation strength only.
 */
export function IncidentCard({ incident, onSelectEvent, className }: IncidentCardProps) {
  const [expanded, setExpanded] = useState(false)
  const tone = priorityTone(incident.priority)
  const confidencePct =
    incident.confidence_score != null
      ? Math.round(incident.confidence_score * (incident.confidence_score <= 1 ? 100 : 1))
      : null

  return (
    <article className={cn('fx-card p-5', className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Badge className={cn(tone.text, tone.bg, tone.border)} dotClassName={tone.dot}>
              Candidate Incident
            </Badge>
            {incident.priority && (
              <span className={cn('text-xs font-medium', tone.text)}>
                {humanize(incident.priority)} priority
              </span>
            )}
          </div>
          <p className="mt-2 font-mono text-xs text-fg-faint">{incident.incident_id}</p>
        </div>
        {confidencePct != null && (
          <div className="text-right">
            <div className="text-lg font-semibold tabular-nums text-fg">
              {confidencePct}%
            </div>
            <div className="text-[11px] text-fg-faint">correlation confidence</div>
          </div>
        )}
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Metric icon={Clock} label="Start" value={formatDateTime(incident.start_time)} />
        <Metric icon={Clock} label="End" value={formatDateTime(incident.end_time)} />
        <Metric icon={Layers} label="Events" value={String(incident.event_ids?.length ?? 0)} />
        <Metric
          icon={GitBranch}
          label="Sources"
          value={incident.sources?.length ? incident.sources.join(', ') : NOT_AVAILABLE}
        />
      </div>

      {incident.correlation_reasons?.length > 0 && (
        <div className="mt-4">
          <p className="text-xs font-medium uppercase tracking-wide text-fg-faint">
            Why these events were grouped
          </p>
          <ul className="mt-1.5 space-y-1">
            {incident.correlation_reasons.map((reason, i) => (
              <li key={i} className="flex gap-2 text-sm text-fg-muted">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-fg-faint" />
                {reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {incident.events?.length > 0 && (
        <div className="mt-4">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-brand hover:text-brand-strong"
            aria-expanded={expanded}
          >
            <ChevronDown
              className={cn('h-4 w-4 transition-transform', expanded && 'rotate-180')}
            />
            {expanded ? 'Hide' : 'Show'} {incident.events.length} correlated events
          </button>
          {expanded && (
            <ul className="mt-3 space-y-2">
              {incident.events.map((event) => (
                <li key={event.id}>
                  <button
                    type="button"
                    onClick={() => onSelectEvent?.(event)}
                    disabled={!onSelectEvent}
                    className={cn(
                      'flex w-full items-center justify-between gap-3 rounded-lg border border-line bg-surface2 px-3 py-2 text-left',
                      onSelectEvent && 'transition-colors hover:border-brand/40 hover:bg-surface3',
                    )}
                  >
                    <span className="min-w-0">
                      <span className="block truncate text-sm text-fg">
                        {event.event_type || NOT_AVAILABLE}
                      </span>
                      <span className="block font-mono text-[11px] text-fg-faint">
                        {formatDateTime(event.timestamp)}
                      </span>
                    </span>
                    <SeverityBadge severity={event.severity} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </article>
  )
}

function Metric({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Clock
  label: string
  value: string
}) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-fg-faint">
        <Icon className="h-3.5 w-3.5" aria-hidden />
        {label}
      </div>
      <div className="mt-0.5 truncate text-sm text-fg" title={value}>
        {value}
      </div>
    </div>
  )
}
