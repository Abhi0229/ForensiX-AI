import type { ReactNode } from 'react'
import { cn } from '@/utils/cn'

interface BadgeProps {
  children: ReactNode
  className?: string
  /** Optional leading dot indicator. */
  dotClassName?: string
  title?: string
}

/** A small pill label. Colors are supplied by the caller via className. */
export function Badge({ children, className, dotClassName, title }: BadgeProps) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5',
        'text-xs font-medium whitespace-nowrap',
        className,
      )}
    >
      {dotClassName && (
        <span className={cn('h-1.5 w-1.5 rounded-full', dotClassName)} aria-hidden />
      )}
      {children}
    </span>
  )
}
