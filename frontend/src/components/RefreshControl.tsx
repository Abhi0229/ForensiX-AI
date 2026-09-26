import { RefreshCw } from 'lucide-react'
import { cn } from '@/utils/cn'
import { formatRelative } from '@/utils/format'

interface RefreshControlProps {
  onRefresh: () => void
  refreshing?: boolean
  lastUpdated?: number | null
  className?: string
}

/** A manual refresh button with a "last updated" hint. */
export function RefreshControl({
  onRefresh,
  refreshing,
  lastUpdated,
  className,
}: RefreshControlProps) {
  return (
    <div className={cn('flex items-center gap-3', className)}>
      {lastUpdated != null && (
        <span className="hidden text-xs text-fg-faint sm:inline">
          Updated {formatRelative(new Date(lastUpdated).toISOString())}
        </span>
      )}
      <button
        type="button"
        onClick={onRefresh}
        disabled={refreshing}
        className={cn(
          'inline-flex items-center gap-2 rounded-lg border border-line bg-surface2 px-3 py-2 text-sm font-medium text-fg-muted',
          'transition-colors hover:bg-surface3 hover:text-fg focus-visible:outline-none disabled:opacity-60',
        )}
      >
        <RefreshCw className={cn('h-4 w-4', refreshing && 'animate-spin')} />
        <span className="hidden sm:inline">Refresh</span>
      </button>
    </div>
  )
}
