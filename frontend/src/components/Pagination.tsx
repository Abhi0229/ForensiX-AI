import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/utils/cn'
import { formatNumber } from '@/utils/format'

interface PaginationProps {
  total: number
  limit: number
  offset: number
  onChange: (offset: number) => void
  className?: string
  /** Label for the counted items, e.g. "events". */
  noun?: string
}

/** Offset/limit pagination control with a range summary. */
export function Pagination({
  total,
  limit,
  offset,
  onChange,
  className,
  noun = 'items',
}: PaginationProps) {
  const safeLimit = Math.max(1, limit)
  const start = total === 0 ? 0 : offset + 1
  const end = Math.min(offset + safeLimit, total)
  const canPrev = offset > 0
  const canNext = offset + safeLimit < total
  const page = Math.floor(offset / safeLimit) + 1
  const pages = Math.max(1, Math.ceil(total / safeLimit))

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-between gap-3 sm:flex-row',
        className,
      )}
    >
      <p className="text-xs text-fg-muted">
        Showing <span className="font-medium text-fg">{formatNumber(start)}</span>–
        <span className="font-medium text-fg">{formatNumber(end)}</span> of{' '}
        <span className="font-medium text-fg">{formatNumber(total)}</span> {noun}
      </p>
      <div className="flex items-center gap-2">
        <span className="text-xs text-fg-faint tabular-nums">
          Page {page} / {pages}
        </span>
        <button
          type="button"
          disabled={!canPrev}
          onClick={() => onChange(Math.max(0, offset - safeLimit))}
          aria-label="Previous page"
          className="inline-flex items-center rounded-lg border border-line bg-surface2 p-1.5 text-fg-muted transition-colors hover:bg-surface3 hover:text-fg disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <button
          type="button"
          disabled={!canNext}
          onClick={() => onChange(offset + safeLimit)}
          aria-label="Next page"
          className="inline-flex items-center rounded-lg border border-line bg-surface2 p-1.5 text-fg-muted transition-colors hover:bg-surface3 hover:text-fg disabled:cursor-not-allowed disabled:opacity-40"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}
