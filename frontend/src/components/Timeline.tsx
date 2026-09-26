import { motion } from 'framer-motion'
import { SeverityBadge } from './SeverityBadge'
import type { EventResponse } from '@/types'
import { cn } from '@/utils/cn'
import { formatDateTime, NOT_AVAILABLE } from '@/utils/format'
import { severityTone, sourceIcon } from '@/utils/severity'
import { useSettings } from '@/hooks/useSettings'

interface TimelineProps {
  events: EventResponse[]
  onSelect?: (event: EventResponse) => void
  className?: string
}

/** A vertical forensic timeline of events, newest first as provided. */
export function Timeline({ events, onSelect, className }: TimelineProps) {
  const { animationsEnabled } = useSettings()
  return (
    <ol className={cn('relative space-y-1', className)}>
      {/* Vertical spine */}
      <span
        className="absolute left-[19px] top-2 bottom-2 w-px bg-line"
        aria-hidden
      />
      {events.map((event, i) => {
        const Icon = sourceIcon(event.source)
        const tone = severityTone(event.severity)
        return (
          <motion.li
            key={event.id}
            initial={animationsEnabled ? { opacity: 0, x: -6 } : false}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.25, delay: Math.min(i * 0.02, 0.25) }}
            className="relative pl-12"
          >
            <span
              className={cn(
                'absolute left-0 top-1.5 flex h-10 w-10 items-center justify-center rounded-full border bg-surface',
                tone.border,
              )}
            >
              <Icon className={cn('h-4.5 w-4.5', tone.text)} aria-hidden />
            </span>
            <button
              type="button"
              onClick={() => onSelect?.(event)}
              disabled={!onSelect}
              className={cn(
                'w-full rounded-lg border border-transparent p-3 text-left transition-colors',
                onSelect && 'hover:border-line hover:bg-surface2 focus-visible:border-line focus-visible:bg-surface2 focus-visible:outline-none',
              )}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-xs text-fg-muted">
                  {formatDateTime(event.timestamp)}
                </span>
                <SeverityBadge severity={event.severity} />
              </div>
              <p className="mt-1 text-sm font-medium text-fg">
                {event.event_type || NOT_AVAILABLE}
              </p>
              <p className="mt-0.5 text-sm text-fg-muted">
                {event.description || NOT_AVAILABLE}
              </p>
              <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-faint">
                <span>Source: {event.source || NOT_AVAILABLE}</span>
                {event.user && <span>User: {event.user}</span>}
                {event.device && <span>Device: {event.device}</span>}
              </div>
            </button>
          </motion.li>
        )
      })}
    </ol>
  )
}
