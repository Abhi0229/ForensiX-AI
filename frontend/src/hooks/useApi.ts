import { useCallback, useEffect, useRef, useState } from 'react'
import { friendlyError } from '@/services/api'

export interface UseApiState<T> {
  data: T | null
  loading: boolean
  /** User-safe error message, or null. */
  error: string | null
  /** Manually re-run the request. */
  refetch: () => void
  /** True while a background refresh (poll/refetch) is in flight. */
  refreshing: boolean
  /** Timestamp (ms) of the last successful load, or null. */
  lastUpdated: number | null
}

export interface UseApiOptions {
  /** Poll interval in ms. 0 / undefined disables polling. */
  pollMs?: number
  /** When false, the request is not issued. */
  enabled?: boolean
}

/**
 * Generic data-fetching hook with abort handling, manual refetch and
 * optional polling. The fetcher receives an AbortSignal and must be stable
 * across renders unless one of `deps` changes.
 */
export function useApi<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: unknown[] = [],
  options: UseApiOptions = {},
): UseApiState<T> {
  const { pollMs = 0, enabled = true } = options
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState<boolean>(enabled)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [nonce, setNonce] = useState(0)

  // Keep the latest fetcher without forcing effect re-runs on identity change.
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher
  const hasLoaded = useRef(false)

  const refetch = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return
    }
    const controller = new AbortController()
    let cancelled = false

    const run = async () => {
      if (hasLoaded.current) setRefreshing(true)
      else setLoading(true)
      try {
        const result = await fetcherRef.current(controller.signal)
        if (cancelled) return
        setData(result)
        setError(null)
        setLastUpdated(Date.now())
        hasLoaded.current = true
      } catch (err) {
        if (cancelled || controller.signal.aborted) return
        setError(friendlyError(err))
      } finally {
        if (!cancelled) {
          setLoading(false)
          setRefreshing(false)
        }
      }
    }

    run()

    let interval: ReturnType<typeof setInterval> | undefined
    if (pollMs && pollMs > 0) {
      interval = setInterval(run, pollMs)
    }

    return () => {
      cancelled = true
      controller.abort()
      if (interval) clearInterval(interval)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, pollMs, enabled])

  return { data, loading, error, refetch, refreshing, lastUpdated }
}
