import { useMemo } from 'react'
import { useTheme } from './useTheme'

/**
 * Chart chrome colors for the active theme.
 *
 * Recharts styles (axis tick fill, grid stroke, tooltip background, etc.) take
 * raw color strings rather than Tailwind classes, so charts cannot rely on the
 * semantic utility tokens. This hook returns theme-appropriate chrome colors
 * derived from the resolved theme; it re-evaluates when the theme changes.
 *
 * Severity / palette *data* colors are intentionally NOT themed here — those
 * encode meaning and stay constant across themes (see utils/severity.ts).
 */
export interface ChartTheme {
  axis: string
  grid: string
  tooltipBg: string
  tooltipBorder: string
  tooltipLabel: string
  tooltipItem: string
  /** Cursor overlay fill/stroke for hovered categories. */
  cursor: string
  /** Brand accent used for line/area strokes and gradients. */
  brand: string
}

const DARK: ChartTheme = {
  axis: '#61708a',
  grid: '#1a2233',
  tooltipBg: '#0f1521',
  tooltipBorder: '#212c40',
  tooltipLabel: '#e7edf7',
  tooltipItem: '#93a1b8',
  cursor: 'rgba(255,255,255,0.04)',
  brand: '#4c8dff',
}

const LIGHT: ChartTheme = {
  axis: '#64748b',
  grid: '#e2e8f0',
  tooltipBg: '#ffffff',
  tooltipBorder: '#d1d8e4',
  tooltipLabel: '#0f1826',
  tooltipItem: '#475569',
  cursor: 'rgba(15,24,38,0.05)',
  brand: '#2563eb',
}

export function useChartTheme(): ChartTheme {
  const { resolvedTheme } = useTheme()
  return useMemo(() => (resolvedTheme === 'light' ? LIGHT : DARK), [resolvedTheme])
}
