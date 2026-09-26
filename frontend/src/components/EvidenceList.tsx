import { SeverityBadge } from './SeverityBadge'
import { SourceBadge } from './SourceBadge'
import type { EvidenceItem } from '@/types'
import { cn } from '@/utils/cn'
import { formatDateTime, NOT_AVAILABLE } from '@/utils/format'

interface EvidenceListProps {
  evidence: EvidenceItem[]
  onSelect?: (id: number) => void
  className?: string
}

/** A list of supporting evidence items, each optionally linking to its event. */
export function EvidenceList({ evidence, onSelect, className }: EvidenceListProps) {
  return (
    <ul className={cn('space-y-2', className)}>
      {evidence.map((item, i) => {
        const id = typeof item.id === 'number' ? item.id : undefined
        const clickable = Boolean(onSelect && id != null)
        const content = (
          <>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <SourceBadge source={item.source ?? null} />
              {item.severity && <SeverityBadge severity={item.severity} />}
            </div>
            <p className="mt-1.5 text-sm text-fg">
              {item.event_type || NOT_AVAILABLE}
            </p>
            {item.description && (
              <p className="mt-0.5 text-sm text-fg-muted">{item.description}</p>
            )}
            <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-fg-faint">
              <span>{formatDateTime(item.timestamp)}</span>
              {id != null && <span>Event #{id}</span>}
              {item.user && <span>User: {item.user}</span>}
            </div>
          </>
        )
        return (
          <li key={id ?? i}>
            {clickable ? (
              <button
                type="button"
                onClick={() => onSelect?.(id as number)}
                className="w-full rounded-lg border border-line bg-surface2 p-3 text-left transition-colors hover:border-brand/40 hover:bg-surface3 focus-visible:outline-none"
              >
                {content}
              </button>
            ) : (
              <div className="rounded-lg border border-line bg-surface2 p-3">
                {content}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
