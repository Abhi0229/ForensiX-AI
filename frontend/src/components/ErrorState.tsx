import { AlertTriangle, RefreshCw } from 'lucide-react'
import { cn } from '@/utils/cn'

interface ErrorStateProps {
  title?: string
  message?: string
  onRetry?: () => void
  className?: string
  compact?: boolean
}

/**
 * A user-safe error state. Displays a friendly message (never a raw stack
 * trace) and an optional Retry action.
 */
export function ErrorState({
  title = 'Unable to load data',
  message = 'Unable to connect to the ForensiX backend. Please check that the API is running and try again.',
  onRetry,
  className,
  compact,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center rounded-card border border-status-danger/30',
        'bg-status-danger/5 text-center',
        compact ? 'px-4 py-6' : 'px-6 py-12',
        className,
      )}
    >
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-status-danger/30 bg-status-danger/10 text-status-danger">
        <AlertTriangle className="h-5 w-5" aria-hidden />
      </div>
      <h3 className="mt-4 text-sm font-semibold text-fg">{title}</h3>
      <p className="mt-1.5 max-w-md text-sm text-fg-muted">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className={cn(
            'mt-5 inline-flex items-center gap-2 rounded-lg border border-line',
            'bg-surface2 px-3.5 py-2 text-sm font-medium text-fg',
            'transition-colors hover:bg-surface3 focus-visible:outline-none',
          )}
        >
          <RefreshCw className="h-4 w-4" aria-hidden />
          Retry
        </button>
      )}
    </div>
  )
}
