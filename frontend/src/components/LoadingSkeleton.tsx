import { cn } from '@/utils/cn'

interface SkeletonProps {
  className?: string
}

/** A single shimmering placeholder block. */
export function Skeleton({ className }: SkeletonProps) {
  return <div className={cn('fx-skeleton h-4 w-full', className)} aria-hidden />
}

/** A stack of skeleton lines for text blocks. */
export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn('space-y-2', className)} aria-hidden>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn('h-3', i === lines - 1 && 'w-2/3')} />
      ))}
    </div>
  )
}

/** A skeleton shaped like a stat/metric card. */
export function SkeletonCard({ className }: SkeletonProps) {
  return (
    <div className={cn('fx-card p-5', className)} aria-busy>
      <Skeleton className="h-3 w-24" />
      <Skeleton className="mt-4 h-8 w-20" />
      <Skeleton className="mt-3 h-3 w-32" />
    </div>
  )
}

/** A skeleton shaped like a table with rows. */
export function SkeletonTable({ rows = 6, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('fx-card overflow-hidden', className)} aria-busy>
      <div className="border-b border-line px-4 py-3">
        <Skeleton className="h-3 w-40" />
      </div>
      <div className="divide-y divide-line-soft">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-3">
            <Skeleton className="h-3 w-28" />
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-3 flex-1" />
            <Skeleton className="h-3 w-16" />
          </div>
        ))}
      </div>
    </div>
  )
}
