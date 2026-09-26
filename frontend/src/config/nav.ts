import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  Boxes,
  BrainCircuit,
  FileText,
  GitBranch,
  LayoutDashboard,
  ListTree,
  Search,
  Settings,
  ShieldCheck,
  Siren,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  /** Optional short description for tooltips / accessibility. */
  description?: string
}

/** Primary navigation. Order defines the sidebar layout. */
export const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, description: 'Overview & key metrics' },
  { to: '/investigate', label: 'Investigate', icon: Search, description: 'Ask the AI investigator' },
  { to: '/events', label: 'Events', icon: ListTree, description: 'Explore raw events' },
  { to: '/timeline', label: 'Timeline', icon: GitBranch, description: 'Chronological view' },
  { to: '/incidents', label: 'Incidents', icon: Siren, description: 'Candidate incidents' },
  { to: '/behavior', label: 'Behavior Analysis', icon: BrainCircuit, description: 'Anomaly detection' },
  { to: '/integrity', label: 'Integrity', icon: ShieldCheck, description: 'Hash-chain verification' },
  { to: '/reports', label: 'Reports', icon: FileText, description: 'Generate reports' },
  { to: '/collectors', label: 'Collectors', icon: Boxes, description: 'Data source status' },
  { to: '/status', label: 'System Status', icon: Activity, description: 'Service health' },
  { to: '/settings', label: 'Settings', icon: Settings, description: 'Preferences' },
]
