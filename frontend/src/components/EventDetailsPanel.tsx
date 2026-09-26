import { useEffect, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { SlideOver } from './SlideOver'
import { Tabs } from './Tabs'
import { SeverityBadge } from './SeverityBadge'
import { SourceBadge } from './SourceBadge'
import { EmptyState } from './EmptyState'
import type { EventResponse } from '@/types'
import { getEvents } from '@/services/api'
import { formatDateTime, NOT_AVAILABLE } from '@/utils/format'
import { cn } from '@/utils/cn'

interface EventDetailsPanelProps {
  event: EventResponse | null
  open: boolean
  onClose: () => void
  /** Callback when a related event is chosen. */
  onSelectRelated?: (event: EventResponse) => void
}

function DetailRow({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="grid grid-cols-3 gap-3 py-2.5">
      <dt className="text-xs font-medium uppercase tracking-wide text-fg-faint">
        {label}
      </dt>
      <dd className="col-span-2 break-words text-sm text-fg">
        {value || <span className="text-fg-faint">{NOT_AVAILABLE}</span>}
      </dd>
    </div>
  )
}

export function EventDetailsPanel({
  event,
  open,
  onClose,
  onSelectRelated,
}: EventDetailsPanelProps) {
  const [tab, setTab] = useState('details')
  const [related, setRelated] = useState<EventResponse[]>([])
  const [relatedLoading, setRelatedLoading] = useState(false)

  useEffect(() => {
    if (open) setTab('details')
  }, [open, event?.id])

  // Fetch other events from the same source as lightweight "related" context.
  useEffect(() => {
    if (!open || tab !== 'related' || !event?.source) return
    const controller = new AbortController()
    setRelatedLoading(true)
    getEvents({ source: event.source, limit: 15 }, controller.signal)
      .then((res) => setRelated(res.events.filter((e) => e.id !== event.id)))
      .catch(() => setRelated([]))
      .finally(() => setRelatedLoading(false))
    return () => controller.abort()
  }, [open, tab, event?.source, event?.id])

  const rawJson = useMemo(() => {
    if (!event) return ''
    try {
      return JSON.stringify(event.metadata ?? {}, null, 2)
    } catch {
      return ''
    }
  }, [event])

  const tabs = [
    { id: 'details', label: 'Details' },
    { id: 'raw', label: 'Raw Data' },
    { id: 'related', label: 'Related Events' },
  ]

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title={event ? event.event_type || `Event #${event.id}` : 'Event'}
      subtitle={
        event && (
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={event.severity} />
            <SourceBadge source={event.source} />
          </div>
        )
      }
    >
      {!event ? (
        <EmptyState title="No event selected" />
      ) : (
        <div className="space-y-4">
          <Tabs tabs={tabs} active={tab} onChange={setTab} />

          {tab === 'details' && (
            <dl className="divide-y divide-line-soft">
              <DetailRow label="Event ID" value={String(event.id)} />
              <DetailRow label="Timestamp" value={formatDateTime(event.timestamp)} />
              <DetailRow label="Source" value={event.source} />
              <DetailRow label="Type" value={event.event_type} />
              <DetailRow label="Severity" value={event.severity} />
              <DetailRow label="Description" value={event.description} />
              <DetailRow label="User" value={event.user} />
              <DetailRow label="Device" value={event.device} />
              <DetailRow label="File Path" value={event.file_path} />
            </dl>
          )}

          {tab === 'raw' && (
            <div>
              <p className="mb-2 text-xs text-fg-muted">
                Raw metadata as recorded by the collector.
              </p>
              {rawJson && rawJson !== '{}' ? (
                <pre className="max-h-[60vh] overflow-auto rounded-lg border border-line bg-base p-4 font-mono text-xs leading-relaxed text-fg-muted">
                  {rawJson}
                </pre>
              ) : (
                <p className="text-sm text-fg-faint">
                  No additional metadata available for this event.
                </p>
              )}
            </div>
          )}

          {tab === 'related' && (
            <div>
              <p className="mb-3 text-xs text-fg-muted">
                Other recent events from{' '}
                <span className="font-medium text-fg">
                  {event.source || NOT_AVAILABLE}
                </span>
                .
              </p>
              {relatedLoading ? (
                <div className="flex items-center gap-2 py-8 text-sm text-fg-muted">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading related events…
                </div>
              ) : related.length === 0 ? (
                <EmptyState
                  title="No related events"
                  message="No other events were found for this source."
                />
              ) : (
                <ul className="space-y-2">
                  {related.map((e) => (
                    <li key={e.id}>
                      <button
                        type="button"
                        onClick={() => onSelectRelated?.(e)}
                        className={cn(
                          'w-full rounded-lg border border-line bg-surface2 p-3 text-left transition-colors',
                          'hover:border-brand/40 hover:bg-surface3 focus-visible:outline-none',
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-sm text-fg">
                            {e.event_type || NOT_AVAILABLE}
                          </span>
                          <SeverityBadge severity={e.severity} />
                        </div>
                        <p className="mt-1 truncate text-xs text-fg-muted">
                          {e.description || NOT_AVAILABLE}
                        </p>
                        <p className="mt-1 font-mono text-[11px] text-fg-faint">
                          {formatDateTime(e.timestamp)}
                        </p>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}
    </SlideOver>
  )
}
