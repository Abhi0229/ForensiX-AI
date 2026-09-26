/**
 * Visual mappings for severities, sources, classifications and statuses.
 * Colors reference the Tailwind theme tokens defined in tailwind.config.js.
 * Nothing here encodes business logic — it is purely presentational.
 */
import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  AlertTriangle,
  Chrome,
  FileText,
  Globe,
  HardDrive,
  KeyRound,
  Monitor,
  Network,
  ScrollText,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  Usb,
} from 'lucide-react'

export interface Tone {
  /** Text color class. */
  text: string
  /** Subtle background (usually with low opacity). */
  bg: string
  /** Border color class. */
  border: string
  /** Solid dot color (for legends / indicators). */
  dot: string
}

const SEVERITY_TONES: Record<string, Tone> = {
  INFO: { text: 'text-sev-info', bg: 'bg-sev-info/10', border: 'border-sev-info/30', dot: 'bg-sev-info' },
  LOW: { text: 'text-sev-low', bg: 'bg-sev-low/10', border: 'border-sev-low/30', dot: 'bg-sev-low' },
  WARNING: { text: 'text-sev-warning', bg: 'bg-sev-warning/10', border: 'border-sev-warning/30', dot: 'bg-sev-warning' },
  MEDIUM: { text: 'text-sev-medium', bg: 'bg-sev-medium/10', border: 'border-sev-medium/30', dot: 'bg-sev-medium' },
  ERROR: { text: 'text-sev-error', bg: 'bg-sev-error/10', border: 'border-sev-error/30', dot: 'bg-sev-error' },
  HIGH: { text: 'text-sev-high', bg: 'bg-sev-high/10', border: 'border-sev-high/30', dot: 'bg-sev-high' },
  CRITICAL: { text: 'text-sev-critical', bg: 'bg-sev-critical/15', border: 'border-sev-critical/40', dot: 'bg-sev-critical' },
  AUDIT_SUCCESS: { text: 'text-status-ok', bg: 'bg-status-ok/10', border: 'border-status-ok/30', dot: 'bg-status-ok' },
  AUDIT_FAILURE: { text: 'text-sev-high', bg: 'bg-sev-high/10', border: 'border-sev-high/30', dot: 'bg-sev-high' },
}

const NEUTRAL_TONE: Tone = {
  text: 'text-fg-muted',
  bg: 'bg-surface3/60',
  border: 'border-line',
  dot: 'bg-fg-faint',
}

/** Tone (color classes) for a severity label. */
export function severityTone(severity?: string | null): Tone {
  if (!severity) return NEUTRAL_TONE
  return SEVERITY_TONES[severity.toUpperCase()] ?? NEUTRAL_TONE
}

/** Approximate ordering weight for sorting severities high → low. */
export function severityWeight(severity?: string | null): number {
  const order: Record<string, number> = {
    CRITICAL: 7,
    HIGH: 6,
    ERROR: 5,
    MEDIUM: 4,
    WARNING: 3,
    AUDIT_FAILURE: 3,
    LOW: 2,
    INFO: 1,
    AUDIT_SUCCESS: 1,
  }
  return order[(severity ?? '').toUpperCase()] ?? 0
}

// ---- Sources ---------------------------------------------------------------

interface SourceMatcher {
  keywords: string[]
  icon: LucideIcon
}

const SOURCE_MATCHERS: SourceMatcher[] = [
  { keywords: ['defender', 'antivirus', 'threat'], icon: ShieldCheck },
  { keywords: ['usb', 'removable'], icon: Usb },
  { keywords: ['browser', 'chrome', 'edge', 'firefox'], icon: Chrome },
  { keywords: ['file', 'filesystem', 'ntfs'], icon: FileText },
  { keywords: ['registry'], icon: ScrollText },
  { keywords: ['network', 'firewall', 'connection', 'dns'], icon: Network },
  { keywords: ['auth', 'logon', 'login', 'credential', 'account'], icon: KeyRound },
  { keywords: ['process', 'sysmon', 'exec'], icon: Terminal },
  { keywords: ['web', 'http', 'url'], icon: Globe },
  { keywords: ['disk', 'drive', 'volume'], icon: HardDrive },
  { keywords: ['windows', 'event', 'eventlog', 'security', 'system'], icon: Monitor },
  { keywords: ['server', 'service'], icon: Server },
]

/** Icon for an event source label (best-effort keyword match). */
export function sourceIcon(source?: string | null): LucideIcon {
  if (!source) return Activity
  const lower = source.toLowerCase()
  for (const m of SOURCE_MATCHERS) {
    if (m.keywords.some((k) => lower.includes(k))) return m.icon
  }
  return Activity
}

// ---- Behavior classifications ---------------------------------------------

const CLASSIFICATION_TONES: Record<string, Tone> = {
  NORMAL: { text: 'text-status-ok', bg: 'bg-status-ok/10', border: 'border-status-ok/30', dot: 'bg-status-ok' },
  SUSPICIOUS: { text: 'text-sev-warning', bg: 'bg-sev-warning/10', border: 'border-sev-warning/30', dot: 'bg-sev-warning' },
  ANOMALOUS: { text: 'text-sev-high', bg: 'bg-sev-high/10', border: 'border-sev-high/30', dot: 'bg-sev-high' },
  INSUFFICIENT_HISTORY: { text: 'text-fg-muted', bg: 'bg-surface3/60', border: 'border-line', dot: 'bg-fg-faint' },
}

export function classificationTone(value?: string | null): Tone {
  if (!value) return NEUTRAL_TONE
  return CLASSIFICATION_TONES[value.toUpperCase()] ?? NEUTRAL_TONE
}

// ---- Integrity statuses ----------------------------------------------------

const INTEGRITY_TONES: Record<string, Tone> = {
  VERIFIED: { text: 'text-status-ok', bg: 'bg-status-ok/10', border: 'border-status-ok/30', dot: 'bg-status-ok' },
  LEGACY: { text: 'text-status-legacy', bg: 'bg-status-legacy/10', border: 'border-status-legacy/30', dot: 'bg-status-legacy' },
  TAMPERED: { text: 'text-status-danger', bg: 'bg-status-danger/10', border: 'border-status-danger/30', dot: 'bg-status-danger' },
  UNVERIFIED: { text: 'text-fg-muted', bg: 'bg-surface3/60', border: 'border-line', dot: 'bg-fg-faint' },
}

export function integrityTone(status?: string | null): Tone {
  if (!status) return NEUTRAL_TONE
  return INTEGRITY_TONES[status.toUpperCase()] ?? NEUTRAL_TONE
}

export function integrityIcon(status?: string | null): LucideIcon {
  const s = (status ?? '').toUpperCase()
  if (s === 'VERIFIED') return ShieldCheck
  if (s === 'TAMPERED') return AlertTriangle
  return Shield
}

// ---- Priority (incidents) --------------------------------------------------

const PRIORITY_TONES: Record<string, Tone> = {
  CRITICAL: { text: 'text-sev-critical', bg: 'bg-sev-critical/15', border: 'border-sev-critical/40', dot: 'bg-sev-critical' },
  HIGH: { text: 'text-sev-high', bg: 'bg-sev-high/10', border: 'border-sev-high/30', dot: 'bg-sev-high' },
  MEDIUM: { text: 'text-sev-medium', bg: 'bg-sev-medium/10', border: 'border-sev-medium/30', dot: 'bg-sev-medium' },
  LOW: { text: 'text-sev-low', bg: 'bg-sev-low/10', border: 'border-sev-low/30', dot: 'bg-sev-low' },
}

export function priorityTone(priority?: string | null): Tone {
  if (!priority) return NEUTRAL_TONE
  return PRIORITY_TONES[priority.toUpperCase()] ?? NEUTRAL_TONE
}

/** Chart-friendly hex colors for severities (Recharts needs raw colors). */
export const SEVERITY_HEX: Record<string, string> = {
  INFO: '#38bdf8',
  LOW: '#2dd4bf',
  WARNING: '#f59e0b',
  MEDIUM: '#fb923c',
  ERROR: '#f87171',
  HIGH: '#ef4444',
  CRITICAL: '#f43f5e',
  AUDIT_SUCCESS: '#22c55e',
  AUDIT_FAILURE: '#ef4444',
}

export function severityHex(severity?: string | null): string {
  return SEVERITY_HEX[(severity ?? '').toUpperCase()] ?? '#64748b'
}

/** A restrained categorical palette for charts (sources, etc.). */
export const CHART_PALETTE = [
  '#4c8dff',
  '#22d3ee',
  '#8b5cf6',
  '#2dd4bf',
  '#f59e0b',
  '#fb923c',
  '#f472b6',
  '#a3e635',
  '#38bdf8',
  '#f87171',
]
