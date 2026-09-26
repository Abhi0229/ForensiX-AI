import type { ReactNode } from 'react'
import { Search, X } from 'lucide-react'
import { cn } from '@/utils/cn'

/** A responsive container that arranges filter controls. */
export function FilterBar({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col gap-3 rounded-card border border-line bg-surface p-3 sm:flex-row sm:flex-wrap sm:items-center',
        className,
      )}
    >
      {children}
    </div>
  )
}

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
  onSubmit?: () => void
}

/** A search text input with a leading icon and a clear button. */
export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
  className,
  onSubmit,
}: SearchInputProps) {
  return (
    <div className={cn('relative flex-1 sm:min-w-[220px]', className)}>
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && onSubmit?.()}
        placeholder={placeholder}
        className="w-full rounded-lg border border-line bg-surface2 py-2 pl-9 pr-9 text-sm text-fg placeholder:text-fg-faint focus:border-brand/50 focus-visible:outline-none"
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          aria-label="Clear search"
          className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-fg-faint hover:text-fg"
        >
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  )
}

interface SelectFilterProps {
  label: string
  value: string
  onChange: (value: string) => void
  options: Array<{ value: string; label: string }>
  className?: string
}

/** A labelled select dropdown for filtering. */
export function SelectFilter({
  label,
  value,
  onChange,
  options,
  className,
}: SelectFilterProps) {
  return (
    <label className={cn('flex items-center gap-2 text-sm', className)}>
      <span className="text-fg-faint">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-line bg-surface2 px-2.5 py-2 text-sm text-fg focus:border-brand/50 focus-visible:outline-none"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </label>
  )
}
