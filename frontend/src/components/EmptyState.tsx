import type { ComponentType, ReactNode } from 'react'
import { Inbox, type LucideProps } from 'lucide-react'
import { cn } from '@/utils/cn'

interface EmptyStateProps {
  icon?: ComponentType<LucideProps>
  title: string
  message?: string
  className?: string
  action?: ReactNode
}

/**
 * A calm, non-misleading empty state. Communicates "no data yet" without
 * implying an error or fabricating content.
 */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  message,
  className,
  action,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center rounded-card border border-dashed',
        'border-line bg-surface/40 px-6 py-14 text-center',
        className,
      )}
    >
      <div className="flex h-12 w-12 items-center justify-center rounded-full border border-line bg-surface2 text-fg-faint">
        <Icon className="h-6 w-6" aria-hidden />
      </div>
      <h3 className="mt-4 text-sm font-semibold text-fg">{title}</h3>
      {message && <p className="mt-1.5 max-w-sm text-sm text-fg-muted">{message}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}
