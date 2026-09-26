import type { ComponentType, ReactNode } from 'react'
import { motion } from 'framer-motion'
import type { LucideProps } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useSettings } from '@/hooks/useSettings'

type Accent = 'brand' | 'cyan' | 'violet' | 'ok' | 'warn' | 'danger' | 'neutral'

interface StatCardProps {
  label: string
  value: ReactNode
  icon?: ComponentType<LucideProps>
  hint?: string
  accent?: Accent
  className?: string
  onClick?: () => void
}

const ACCENTS: Record<Accent, { icon: string; ring: string }> = {
  brand: { icon: 'text-brand bg-brand/10 border-brand/25', ring: 'hover:border-brand/40' },
  cyan: { icon: 'text-cyan bg-cyan/10 border-cyan/25', ring: 'hover:border-cyan/40' },
  violet: { icon: 'text-violet bg-violet/10 border-violet/25', ring: 'hover:border-violet/40' },
  ok: { icon: 'text-status-ok bg-status-ok/10 border-status-ok/25', ring: 'hover:border-status-ok/40' },
  warn: { icon: 'text-status-warn bg-status-warn/10 border-status-warn/25', ring: 'hover:border-status-warn/40' },
  danger: { icon: 'text-status-danger bg-status-danger/10 border-status-danger/25', ring: 'hover:border-status-danger/40' },
  neutral: { icon: 'text-fg-muted bg-surface3/60 border-line', ring: 'hover:border-line' },
}

/** A KPI metric card. Values are supplied by the caller (never fabricated). */
export function StatCard({
  label,
  value,
  icon: Icon,
  hint,
  accent = 'brand',
  className,
  onClick,
}: StatCardProps) {
  const { animationsEnabled } = useSettings()
  const tone = ACCENTS[accent]
  const interactive = Boolean(onClick)

  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <span className="text-xs font-medium uppercase tracking-wide text-fg-faint">
          {label}
        </span>
        {Icon && (
          <span
            className={cn(
              'flex h-9 w-9 items-center justify-center rounded-lg border',
              tone.icon,
            )}
          >
            <Icon className="h-4.5 w-4.5" aria-hidden />
          </span>
        )}
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight text-fg tabular-nums">
        {value}
      </div>
      {hint && <p className="mt-1.5 text-xs text-fg-muted">{hint}</p>}
    </>
  )

  const classes = cn(
    'fx-card p-5 text-left transition-colors',
    tone.ring,
    interactive && 'cursor-pointer',
    className,
  )

  if (interactive) {
    return (
      <motion.button
        type="button"
        onClick={onClick}
        whileHover={animationsEnabled ? { y: -2 } : undefined}
        transition={{ duration: 0.15 }}
        className={classes}
      >
        {body}
      </motion.button>
    )
  }
  return <div className={classes}>{body}</div>
}
