/**
 * Formatting helpers for timestamps, numbers, and labels.
 * All functions are defensive: unknown / null inputs yield graceful fallbacks
 * rather than throwing, and never render as "Invalid Date".
 */

const FALLBACK = 'Not available'

/** Parse a backend timestamp string into a Date, or null if unparseable. */
export function parseDate(value?: string | null): Date | null {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

/** Full, human-readable date + time (local). */
export function formatDateTime(value?: string | null): string {
  const d = parseDate(value)
  if (!d) return FALLBACK
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Compact date + time for dense tables. */
export function formatCompact(value?: string | null): string {
  const d = parseDate(value)
  if (!d) return FALLBACK
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Time only (HH:MM:SS). */
export function formatTime(value?: string | null): string {
  const d = parseDate(value)
  if (!d) return FALLBACK
  return d.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Date only (e.g. "Sep 26, 2026"). */
export function formatDate(value?: string | null): string {
  const d = parseDate(value)
  if (!d) return FALLBACK
  return d.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  })
}

/** Relative time such as "3m ago" / "in 2h". */
export function formatRelative(value?: string | null): string {
  const d = parseDate(value)
  if (!d) return FALLBACK
  const diffMs = d.getTime() - Date.now()
  const abs = Math.abs(diffMs)
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 31536000000],
    ['day', 86400000],
    ['hour', 3600000],
    ['minute', 60000],
    ['second', 1000],
  ]
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === 'second') {
      return rtf.format(Math.round(diffMs / ms), unit)
    }
  }
  return FALLBACK
}

/** Group a numeric count with thousands separators. */
export function formatNumber(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  return value.toLocaleString()
}

/** Render an arbitrary value as safe display text, or a fallback. */
export function displayValue(value: unknown, fallback = FALLBACK): string {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return fallback
  }
}

/** Convert SNAKE_CASE / snake_case to Title Case for labels. */
export function humanize(value?: string | null): string {
  if (!value) return FALLBACK
  return value
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Weekday index (0=Mon per backend) to a short name. */
export function weekdayName(index?: number | null): string {
  if (index === null || index === undefined) return FALLBACK
  const names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
  return names[index] ?? String(index)
}

export const NOT_AVAILABLE = FALLBACK
