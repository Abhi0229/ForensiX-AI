import { cn } from '@/utils/cn'
import { sourceIcon } from '@/utils/severity'
import { NOT_AVAILABLE } from '@/utils/format'

interface SourceBadgeProps {
  source?: string | null
  className?: string
  /** Show only the icon (compact). */
  iconOnly?: boolean
}

/** A source label prefixed with a best-effort icon. */
export function SourceBadge({ source, className, iconOnly }: SourceBadgeProps) {
  const Icon = sourceIcon(source)
  const label = source || NOT_AVAILABLE
  if (iconOnly) {
    return (
      <span
        className={cn('inline-flex items-center text-fg-muted', className)}
        title={label}
        aria-label={label}
      >
        <Icon className="h-4 w-4" />
      </span>
    )
  }
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-sm text-fg-muted',
        className,
      )}
      title={label}
    >
      <Icon className="h-4 w-4 shrink-0 text-fg-faint" aria-hidden />
      <span className="truncate">{label}</span>
    </span>
  )
}
