import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

/**
 * Theme preference, persisted separately from the rest of the UI settings so
 * the inline bootstrap script in index.html can read it synchronously and set
 * the theme class before React hydrates (no flash of the wrong theme).
 *
 *   'dark'   — the baseline forensic identity (default)
 *   'light'  — a professional high-contrast light theme
 *   'system' — follow the OS / browser color-scheme preference
 */
export type ThemePreference = 'dark' | 'light' | 'system'
export type ResolvedTheme = 'dark' | 'light'

const STORAGE_KEY = 'forensix.theme'
const DEFAULT_THEME: ThemePreference = 'dark'
const DARK_QUERY = '(prefers-color-scheme: dark)'

interface ThemeContextValue {
  /** The user's chosen preference. */
  theme: ThemePreference
  /** The concrete theme currently applied ('system' resolved to dark/light). */
  resolvedTheme: ResolvedTheme
  /** Change and persist the preference. */
  setTheme: (theme: ThemePreference) => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function prefersDark(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return true
  return window.matchMedia(DARK_QUERY).matches
}

function loadInitial(): ThemePreference {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw === 'dark' || raw === 'light' || raw === 'system') return raw
  } catch {
    /* localStorage unavailable */
  }
  return DEFAULT_THEME
}

function resolve(theme: ThemePreference): ResolvedTheme {
  if (theme === 'system') return prefersDark() ? 'dark' : 'light'
  return theme
}

/** Apply the resolved theme to <html> (class + native color-scheme). */
function applyTheme(resolved: ResolvedTheme): void {
  if (typeof document === 'undefined') return
  const cl = document.documentElement.classList
  cl.remove('dark', 'light')
  cl.add(resolved)
  document.documentElement.style.colorScheme = resolved
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemePreference>(loadInitial)
  const [resolvedTheme, setResolvedTheme] = useState<ResolvedTheme>(() =>
    resolve(loadInitial()),
  )

  // Apply and persist whenever the preference changes.
  useEffect(() => {
    const resolved = resolve(theme)
    setResolvedTheme(resolved)
    applyTheme(resolved)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore persistence failures */
    }
  }, [theme])

  // While following the system, react live to OS preference changes.
  useEffect(() => {
    if (theme !== 'system') return
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mql = window.matchMedia(DARK_QUERY)
    const handler = () => {
      const resolved = prefersDark() ? 'dark' : 'light'
      setResolvedTheme(resolved)
      applyTheme(resolved)
    }
    mql.addEventListener('change', handler)
    return () => mql.removeEventListener('change', handler)
  }, [theme])

  const setTheme = useCallback((next: ThemePreference) => {
    setThemeState(next)
  }, [])

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, resolvedTheme, setTheme }),
    [theme, resolvedTheme, setTheme],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within a ThemeProvider')
  return ctx
}
