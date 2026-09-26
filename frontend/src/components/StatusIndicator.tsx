import { cn } from '@/utils/cn'

type State = 'online' | 'warning' | 'offline' | 'unknown'

interface StatusIndicatorProps {
  state: State
  label: string
  className?: string
  /** Animate the dot (subtle pulse) for the online state. */
  pulse?: boolean
}

const STATE_TONES: Record<State, { dot: string; text: string }> = {
  online: { dot: 'bg-status-ok', text: 'text-status-ok' },
  warning: { dot: 'bg-status-warn', text: 'text-status-warn' },
  offline: { dot: 'bg-status-danger', text: 'text-status-danger' },
  unknown: { dot: 'bg-status-legacy', text: 'text-fg-muted' },
}

/** A small dot + label status indicator (no color-only meaning: label included). */
export function StatusIndicator({ state, label, className, pulse }: StatusIndicatorProps) {
  const tone = STATE_TONES[state]
  return (
    <span className={cn('inline-flex items-center gap-2 text-sm', className)}>
      <span className="relative flex h-2 w-2">
        {pulse && state === 'online' && (
          <span
            className={cn(
              'absolute inline-flex h-full w-full animate-ping rounded-full opacity-60',
              tone.dot,
            )}
          />
        )}
        <span className={cn('relative inline-flex h-2 w-2 rounded-full', tone.dot)} />
      </span>
      <span className={cn('font-medium', tone.text)}>{label}</span>
    </span>
  )
}
