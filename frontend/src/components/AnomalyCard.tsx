import { AlertTriangle } from 'lucide-react'
import { Badge } from './Badge'
import { SeverityBadge } from './SeverityBadge'
import type { BehaviorAnomalyResponse } from '@/types'
import { cn } from '@/utils/cn'
import { formatDateTime, humanize, NOT_AVAILABLE, weekdayName } from '@/utils/format'
import { classificationTone } from '@/utils/severity'

interface AnomalyCardProps {
  anomaly: BehaviorAnomalyResponse
  className?: string
}

/** Normalize an anomaly score to a 0–100 bar width (best-effort, presentational). */
function scoreToPct(score?: number | null): number | null {
  if (score == null || Number.isNaN(score)) return null
  const pct = score <= 1 ? score * 100 : score
  return Math.max(0, Math.min(100, pct))
}

/**
 * A behavioral anomaly card. The score is a relative deviation measure — NOT a
 * probability of malicious activity. An anomaly is not a confirmed threat.
 */
export function AnomalyCard({ anomaly, className }: AnomalyCardProps) {
  const tone = classificationTone(anomaly.classification)
  const pct = scoreToPct(anomaly.anomaly_score)
  const ev = anomaly.event

  return (
    <article className={cn('fx-card p-5', className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <Badge className={cn(tone.text, tone.bg, tone.border)} dotClassName={tone.dot}>
            {humanize(anomaly.classification)}
          </Badge>
          {anomaly.severity && <SeverityBadge severity={anomaly.severity} />}
        </div>
        {anomaly.anomaly_score != null && (
          <div className="text-right">
            <div className="text-lg font-semibold tabular-nums text-fg">
              {anomaly.anomaly_score.toFixed(2)}
            </div>
            <div className="text-[11px] text-fg-faint">anomaly score</div>
          </div>
        )}
      </div>

      {pct != null && (
        <div className="mt-4">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface3">
            <div
              className={cn('h-full rounded-full', tone.dot)}
              style={{ width: `${pct}%` }}
            />
          </div>
          <p className="mt-1.5 text-[11px] text-fg-faint">
            Relative deviation from the learned baseline — not a probability of malicious activity.
          </p>
        </div>
      )}

      <div className="mt-4 rounded-lg border border-line bg-surface2 p-3">
        <p className="text-sm font-medium text-fg">
          {ev?.event_type || NOT_AVAILABLE}
        </p>
        <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-fg-muted sm:grid-cols-3">
          <span>Source: {ev?.source || NOT_AVAILABLE}</span>
          <span>User: {ev?.user || NOT_AVAILABLE}</span>
          <span>Device: {ev?.device || NOT_AVAILABLE}</span>
          <span>When: {formatDateTime(ev?.timestamp)}</span>
          {ev?.hour != null && <span>Hour: {ev.hour}:00</span>}
          {ev?.weekday != null && <span>Day: {weekdayName(ev.weekday)}</span>}
        </div>
      </div>

      {anomaly.reasons?.length > 0 && (
        <div className="mt-4">
          <p className="text-xs font-medium uppercase tracking-wide text-fg-faint">
            Contributing signals
          </p>
          <ul className="mt-1.5 space-y-1">
            {anomaly.reasons.map((reason, i) => (
              <li key={i} className="flex gap-2 text-sm text-fg-muted">
                <AlertTriangle className={cn('mt-0.5 h-3.5 w-3.5 shrink-0', tone.text)} />
                {reason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  )
}
