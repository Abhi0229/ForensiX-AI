import { NavLink } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { Fingerprint, X } from 'lucide-react'
import { NAV_ITEMS } from '@/config/nav'
import { cn } from '@/utils/cn'
import { useSettings } from '@/hooks/useSettings'

interface SidebarProps {
  collapsed: boolean
  mobileOpen: boolean
  onMobileClose: () => void
}

function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <div className={cn('flex items-center gap-2.5 px-4', collapsed ? 'justify-center px-0' : '')}>
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-brand/30 bg-brand/10 text-brand shadow-glow-brand">
        <Fingerprint className="h-5 w-5" />
      </span>
      {!collapsed && (
        <span className="min-w-0">
          <span className="block text-sm font-semibold leading-tight text-fg">
            ForensiX <span className="text-brand">AI</span>
          </span>
          <span className="block text-[11px] leading-tight text-fg-faint">
            DFIR Investigation
          </span>
        </span>
      )}
    </div>
  )
}

function NavList({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  return (
    <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4" aria-label="Primary">
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            onClick={onNavigate}
            title={collapsed ? item.label : undefined}
            className={({ isActive }) =>
              cn(
                'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                collapsed && 'justify-center px-0',
                isActive
                  ? 'bg-brand/10 text-fg'
                  : 'text-fg-muted hover:bg-surface2 hover:text-fg',
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r-full bg-brand" />
                )}
                <Icon
                  className={cn('h-[18px] w-[18px] shrink-0', isActive && 'text-brand')}
                  aria-hidden
                />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </>
            )}
          </NavLink>
        )
      })}
    </nav>
  )
}

function Footer({ collapsed }: { collapsed: boolean }) {
  if (collapsed) return null
  return (
    <div className="border-t border-line-soft px-4 py-3">
      <p className="text-[11px] leading-relaxed text-fg-faint">
        Local, private analysis. All processing stays on this endpoint.
      </p>
    </div>
  )
}

/**
 * The primary sidebar. On desktop it is a persistent rail that can collapse to
 * icons; on mobile it becomes an overlay drawer.
 */
export function Sidebar({ collapsed, mobileOpen, onMobileClose }: SidebarProps) {
  const { animationsEnabled } = useSettings()

  return (
    <>
      {/* Desktop rail */}
      <aside
        className={cn(
          'hidden shrink-0 flex-col border-r border-line bg-surface/60 backdrop-blur-sm transition-[width] duration-200 lg:flex',
          collapsed ? 'w-[76px]' : 'w-64',
        )}
      >
        <div className="flex h-16 items-center border-b border-line-soft">
          <Brand collapsed={collapsed} />
        </div>
        <NavList collapsed={collapsed} />
        <Footer collapsed={collapsed} />
      </aside>

      {/* Mobile drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <div className="fixed inset-0 z-40 lg:hidden">
            <motion.div
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: animationsEnabled ? 0.2 : 0 }}
              onClick={onMobileClose}
            />
            <motion.aside
              className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-line bg-surface"
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ duration: animationsEnabled ? 0.25 : 0, ease: [0.22, 1, 0.36, 1] }}
            >
              <div className="flex h-16 items-center justify-between border-b border-line-soft pr-3">
                <Brand collapsed={false} />
                <button
                  type="button"
                  onClick={onMobileClose}
                  aria-label="Close navigation"
                  className="rounded-lg p-1.5 text-fg-muted hover:bg-surface2 hover:text-fg"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              <NavList collapsed={false} onNavigate={onMobileClose} />
              <Footer collapsed={false} />
            </motion.aside>
          </div>
        )}
      </AnimatePresence>
    </>
  )
}
