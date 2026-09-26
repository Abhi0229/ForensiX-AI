import { Badge } from './Badge'
import type { IntegrityResponse } from '@/types'
import { cn } from '@/utils/cn'
import { formatNumber, humanize } from '@/utils/format'
import { integrityIcon, integrityTone } from '@/utils/severity'

interface IntegrityStatusProps {
  integrity: IntegrityResponse
  className?: string
  /** Show the explanatory footnote and error list. */
  detailed?: boolean
}

const STATUS_EXPLANATIONS: Record<string, string> = {
  VERIFIED:
    'Every hashed event links correctly to the previous one. The chain shows no signs of tampering.',
  LEGACY:
    'Some events predate hash-chaining and cannot be cryptographically verified, but no tampering was detected among hashed events.',
  TAMPERED:
    'One or more events break the hash chain. The stored data may have been altered after collection.',
  UNVERIFIED:
    'The hash chain has not been verified, or there is not enough hashed data to evaluate.',
}

/** Visualizes the tamper-evident hash-chain integrity of the event store. */
export function IntegrityStatus({ integrity, className, detailed }: IntegrityStatusProps) {
  const tone = integrityTone(integrity.status)
  const Icon = integrityIcon(integrity.status)
  const total = Math.max(1, integrity.total_events || 0)
  const hashedPct = ((integrity.hashed_events || 0) / total) * 100
  const legacyPct = ((integrity.legacy_events || 0) / total) * 100
  const invalidPct = ((integrity.invalid_events || 0) / total) * 100

  return (
    <div className={cn('fx-card p-5', className)}>
      <div className="flex items-center gap-3">
        <span
          className={cn(
            'flex h-11 w-11 items-center justify-center rounded-lg border',
            tone.bg,
            tone.border,
            tone.text,
          )}
        >
          <Icon className="h-5 w-5" aria-hidden />
        </span>
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-fg">Hash-chain integrity</h3>
            <Badge className={cn(tone.text, tone.bg, tone.border)} dotClassName={tone.dot}>
              {humanize(integrity.status)}
            </Badge>
          </div>
          <p className="mt-0.5 text-xs text-fg-muted">
            {integrity.valid
              ? 'Chain verification passed'
              : 'Chain verification did not fully pass'}
          </p>
        </div>
      </div>

      {/* Composition bar: hashed / legacy / invalid */}
      <div className="mt-5">
        <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface3">
          <div className="h-full bg-status-ok" style={{ width: `${hashedPct}%` }} title="Hashed" />
          <div className="h-full bg-status-legacy" style={{ width: `${legacyPct}%` }} title="Legacy" />
          <div className="h-full bg-status-danger" style={{ width: `${invalidPct}%` }} title="Invalid" />
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-fg-muted">
          <LegendDot className="bg-status-ok" label={`Hashed ${formatNumber(integrity.hashed_events)}`} />
          <LegendDot className="bg-status-legacy" label={`Legacy ${formatNumber(integrity.legacy_events)}`} />
          <LegendDot className="bg-status-danger" label={`Invalid ${formatNumber(integrity.invalid_events)}`} />
        </div>
      </div>

      <dl className="mt-5 grid grid-cols-3 gap-3">
        <Stat label="Total" value={formatNumber(integrity.total_events)} />
        <Stat label="Checked" value={formatNumber(integrity.checked_events)} />
        <Stat label="Hashed" value={formatNumber(integrity.hashed_events)} />
      </dl>

      {detailed && (
        <>
          <p className="mt-5 rounded-lg border border-line bg-surface2 p-3 text-xs leading-relaxed text-fg-muted">
            {STATUS_EXPLANATIONS[(integrity.status || '').toUpperCase()] ??
              'Integrity status could not be interpreted.'}
          </p>
          {integrity.errors?.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-medium uppercase tracking-wide text-status-danger">
                Reported issues
              </p>
              <ul className="mt-1.5 space-y-1">
                {integrity.errors.map((err, i) => (
                  <li key={i} className="font-mono text-xs text-status-danger/90">
                    {err}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface2 px-3 py-2.5 text-center">
      <div className="text-lg font-semibold tabular-nums text-fg">{value}</div>
      <div className="text-[11px] uppercase tracking-wide text-fg-faint">{label}</div>
    </div>
  )
}

function LegendDot({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn('h-2 w-2 rounded-full', className)} aria-hidden />
      {label}
    </span>
  )
}
