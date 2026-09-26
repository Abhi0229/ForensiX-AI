import type { ReactNode } from 'react'
import { cn } from '@/utils/cn'

interface ChartCardProps {
  title: string
  description?: string
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}

/** A titled surface used to frame a chart or visualization. */
export function ChartCard({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
}: ChartCardProps) {
  return (
    <section className={cn('fx-card flex flex-col', className)}>
      <header className="flex items-start justify-between gap-3 border-b border-line-soft px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-fg">{title}</h2>
          {description && (
            <p className="mt-0.5 text-xs text-fg-muted">{description}</p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </header>
      <div className={cn('flex-1 p-5', bodyClassName)}>{children}</div>
    </section>
  )
}
