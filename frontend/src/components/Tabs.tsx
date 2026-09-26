import { cn } from '@/utils/cn'

export interface TabItem {
  id: string
  label: string
  count?: number
}

interface TabsProps {
  tabs: TabItem[]
  active: string
  onChange: (id: string) => void
  className?: string
}

/** An accessible, keyboard-navigable tab strip. */
export function Tabs({ tabs, active, onChange, className }: TabsProps) {
  return (
    <div
      role="tablist"
      aria-orientation="horizontal"
      className={cn('flex items-center gap-1 border-b border-line', className)}
    >
      {tabs.map((tab) => {
        const selected = tab.id === active
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={selected}
            onClick={() => onChange(tab.id)}
            className={cn(
              'relative -mb-px inline-flex items-center gap-2 px-3.5 py-2.5 text-sm font-medium',
              'transition-colors focus-visible:outline-none',
              selected
                ? 'text-fg'
                : 'text-fg-muted hover:text-fg',
            )}
          >
            {tab.label}
            {typeof tab.count === 'number' && (
              <span
                className={cn(
                  'rounded-full px-1.5 py-0.5 text-[11px] tabular-nums',
                  selected ? 'bg-brand/15 text-brand' : 'bg-surface3 text-fg-faint',
                )}
              >
                {tab.count}
              </span>
            )}
            {selected && (
              <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-brand" />
            )}
          </button>
        )
      })}
    </div>
  )
}
