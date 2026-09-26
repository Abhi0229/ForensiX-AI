import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, Menu, PanelLeft, Search, ShieldHalf } from 'lucide-react'
import { StatusIndicator } from '@/components/StatusIndicator'
import { getHealth } from '@/services/api'
import { useApi } from '@/hooks/useApi'
import { cn } from '@/utils/cn'

interface TopbarProps {
  onToggleCollapse: () => void
  onOpenMobile: () => void
}

/** A live clock (updates each second). */
function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

export function Topbar({ onToggleCollapse, onOpenMobile }: TopbarProps) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const now = useClock()

  // Poll health every 20s to drive the system status indicator.
  const { data: health, error } = useApi((signal) => getHealth(signal), [], {
    pollMs: 20000,
  })

  const online = !error && !!health
  const state = error ? 'offline' : health ? 'online' : 'unknown'
  const label = online ? 'System Online' : error ? 'Backend Offline' : 'Checking…'

  const submitSearch = () => {
    const q = query.trim()
    if (!q) return
    navigate(`/investigate?q=${encodeURIComponent(q)}`)
    setQuery('')
  }

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-line fx-glass px-4 sm:px-6">
      {/* Sidebar toggles */}
      <button
        type="button"
        onClick={onOpenMobile}
        aria-label="Open navigation"
        className="rounded-lg p-2 text-fg-muted hover:bg-surface2 hover:text-fg lg:hidden"
      >
        <Menu className="h-5 w-5" />
      </button>
      <button
        type="button"
        onClick={onToggleCollapse}
        aria-label="Toggle sidebar"
        className="hidden rounded-lg p-2 text-fg-muted hover:bg-surface2 hover:text-fg lg:inline-flex"
      >
        <PanelLeft className="h-5 w-5" />
      </button>

      {/* Global investigation search */}
      <div className="relative flex-1 max-w-xl">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submitSearch()}
          placeholder="Investigate… e.g. “failed logons in the last day”"
          aria-label="Investigation search"
          className="w-full rounded-lg border border-line bg-surface2/80 py-2 pl-9 pr-3 text-sm text-fg placeholder:text-fg-faint focus:border-brand/50 focus-visible:outline-none"
        />
      </div>

      <div className="flex items-center gap-2 sm:gap-3">
        <StatusIndicator
          state={state}
          label={label}
          pulse
          className="hidden sm:inline-flex"
        />

        {/* Clock */}
        <div className="hidden text-right md:block">
          <div className="text-sm font-medium tabular-nums text-fg">
            {now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </div>
          <div className="text-[11px] text-fg-faint">
            {now.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}
          </div>
        </div>

        <button
          type="button"
          aria-label="Notifications"
          className="relative rounded-lg p-2 text-fg-muted hover:bg-surface2 hover:text-fg"
        >
          <Bell className="h-5 w-5" />
        </button>

        {/* User / admin menu (local, single-analyst context) */}
        <button
          type="button"
          className={cn(
            'flex items-center gap-2 rounded-lg border border-line bg-surface2 py-1.5 pl-1.5 pr-2.5 text-sm',
            'text-fg-muted transition-colors hover:text-fg',
          )}
          aria-label="Analyst menu"
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-brand/15 text-brand">
            <ShieldHalf className="h-4 w-4" />
          </span>
          <span className="hidden font-medium sm:inline">Analyst</span>
        </button>
      </div>
    </header>
  )
}
