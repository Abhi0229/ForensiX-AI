import { motion } from 'framer-motion'
import { SeverityBadge } from './SeverityBadge'
import { SourceBadge } from './SourceBadge'
import type { EventResponse } from '@/types'
import { cn } from '@/utils/cn'
import { formatCompact, NOT_AVAILABLE } from '@/utils/format'
import { useSettings } from '@/hooks/useSettings'

interface EventTableProps {
  events: EventResponse[]
  onSelect?: (event: EventResponse) => void
  selectedId?: number | null
  className?: string
}

/** A dense, keyboard-navigable table of forensic events. */
export function EventTable({ events, onSelect, selectedId, className }: EventTableProps) {
  const { animationsEnabled } = useSettings()
  return (
    <div className={cn('fx-card overflow-hidden', className)}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-line text-left text-xs uppercase tracking-wide text-fg-faint">
              <th className="px-4 py-3 font-medium">Time</th>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Description</th>
              <th className="px-4 py-3 font-medium">User</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-soft">
            {events.map((event, i) => {
              const selected = selectedId === event.id
              return (
                <motion.tr
                  key={event.id}
                  initial={animationsEnabled ? { opacity: 0 } : false}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.2, delay: Math.min(i * 0.015, 0.2) }}
                  tabIndex={onSelect ? 0 : undefined}
                  role={onSelect ? 'button' : undefined}
                  aria-label={onSelect ? `View event ${event.id}` : undefined}
                  onClick={() => onSelect?.(event)}
                  onKeyDown={(e) => {
                    if (onSelect && (e.key === 'Enter' || e.key === ' ')) {
                      e.preventDefault()
                      onSelect(event)
                    }
                  }}
                  className={cn(
                    'align-top transition-colors',
                    onSelect && 'cursor-pointer hover:bg-surface2/70 focus-visible:bg-surface2 focus-visible:outline-none',
                    selected && 'bg-brand-soft/40',
                  )}
                >
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-fg-muted">
                    {formatCompact(event.timestamp)}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={event.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <SourceBadge source={event.source} />
                  </td>
                  <td className="px-4 py-3 text-fg">
                    <span className="block max-w-[14rem] truncate">
                      {event.event_type || NOT_AVAILABLE}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-fg-muted">
                    <span className="block max-w-[24rem] truncate">
                      {event.description || NOT_AVAILABLE}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-fg-muted">
                    {event.user || NOT_AVAILABLE}
                  </td>
                </motion.tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
