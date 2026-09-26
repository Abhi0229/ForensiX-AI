import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { getApiBase, setApiBase as persistApiBase } from '@/services/api'

/**
 * UI-level preferences only. These settings never modify backend behavior —
 * they control the frontend's appearance and polling cadence.
 */
export interface Settings {
  /** Enable Framer Motion / CSS animations. */
  animationsEnabled: boolean
  /** Collapse the desktop sidebar to icons only. */
  sidebarCollapsed: boolean
  /** Auto-refresh interval in ms (0 = manual refresh only). */
  refreshIntervalMs: number
  /** Active API base URL (mirrors the api service). */
  apiBase: string
}

const STORAGE_KEY = 'forensix.settings'

const DEFAULTS: Settings = {
  animationsEnabled: true,
  sidebarCollapsed: false,
  refreshIntervalMs: 0,
  apiBase: '/api',
}

interface SettingsContextValue extends Settings {
  update: (patch: Partial<Settings>) => void
  reset: () => void
}

const SettingsContext = createContext<SettingsContextValue | null>(null)

function loadInitial(): Settings {
  const base = { ...DEFAULTS, apiBase: getApiBase() }
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<Settings>
      return { ...base, ...parsed, apiBase: getApiBase() }
    }
  } catch {
    /* ignore malformed storage */
  }
  return base
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(loadInitial)

  useEffect(() => {
    try {
      const { apiBase, ...rest } = settings
      localStorage.setItem(STORAGE_KEY, JSON.stringify(rest))
      void apiBase
    } catch {
      /* ignore persistence failures */
    }
  }, [settings])

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch }
      if (patch.apiBase !== undefined) {
        persistApiBase(patch.apiBase)
        next.apiBase = getApiBase()
      }
      return next
    })
  }, [])

  const reset = useCallback(() => {
    persistApiBase('')
    setSettings({ ...DEFAULTS, apiBase: getApiBase() })
  }, [])

  const value = useMemo<SettingsContextValue>(
    () => ({ ...settings, update, reset }),
    [settings, update, reset],
  )

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within a SettingsProvider')
  return ctx
}
