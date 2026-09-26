/**
 * ForensiX AI — centralized API client.
 *
 * All backend communication flows through this module. Components never
 * call fetch() directly. Responses are typed against src/types and treated
 * as untrusted data by consumers (rendered as text, never as HTML).
 *
 * Base URL resolution order:
 *   1. localStorage 'forensix.apiBase' (set via Settings)
 *   2. import.meta.env.VITE_API_BASE (build-time)
 *   3. '/api' (same-origin; dev server proxies to the FastAPI backend)
 */
import type {
  BehaviorQuery,
  BehaviorResponse,
  DashboardSummaryResponse,
  EventListResponse,
  EventQuery,
  EventResponse,
  HealthResponse,
  IncidentListResponse,
  IntegrityResponse,
  InvestigateRequest,
  InvestigationReportResponse,
  InvestigationResponse,
  ReportRequest,
  ReportTextResponse,
  TimelineQuery,
  TimelineResponse,
} from '@/types'

const API_BASE_STORAGE_KEY = 'forensix.apiBase'

/** Resolve the active API base URL (no trailing slash). */
export function getApiBase(): string {
  try {
    const stored = localStorage.getItem(API_BASE_STORAGE_KEY)
    if (stored && stored.trim()) return stored.trim().replace(/\/+$/, '')
  } catch {
    /* localStorage may be unavailable; fall through to defaults. */
  }
  const env = (import.meta as any)?.env?.VITE_API_BASE as string | undefined
  if (env && env.trim()) return env.trim().replace(/\/+$/, '')
  return '/api'
}

/** Persist a custom API base URL (used by Settings). */
export function setApiBase(value: string): void {
  try {
    if (value && value.trim()) {
      localStorage.setItem(API_BASE_STORAGE_KEY, value.trim().replace(/\/+$/, ''))
    } else {
      localStorage.removeItem(API_BASE_STORAGE_KEY)
    }
  } catch {
    /* ignore persistence failures */
  }
}

/** A normalized API error with a user-safe message (no stack traces). */
export class ApiError extends Error {
  status: number
  detail?: string
  constructor(message: string, status: number, detail?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

/** A human-friendly, non-technical message for any failure. */
export function friendlyError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 0) {
      return 'Unable to connect to the ForensiX backend. Is the API running?'
    }
    if (err.status === 404) return 'The requested resource was not found.'
    if (err.status >= 500) return 'The ForensiX backend reported an internal error.'
    return err.detail || err.message || 'The request could not be completed.'
  }
  if (err instanceof Error && err.name === 'AbortError') {
    return 'The request timed out. The backend may be busy or unreachable.'
  }
  return 'Something went wrong while contacting the ForensiX backend.'
}

/** Build a query string from a params object, skipping empty values. */
function buildQuery(params?: object): string {
  if (!params) return ''
  const usp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    usp.append(key, String(value))
  }
  const s = usp.toString()
  return s ? `?${s}` : ''
}

interface RequestOptions {
  method?: string
  body?: unknown
  timeoutMs?: number
  signal?: AbortSignal
}

/** Core request helper: JSON in/out, timeout, normalized errors. */
async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, timeoutMs = 30000, signal } = options
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  if (signal) {
    if (signal.aborted) controller.abort()
    else signal.addEventListener('abort', () => controller.abort(), { once: true })
  }

  let res: Response
  try {
    res = await fetch(`${getApiBase()}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    })
  } catch (err) {
    clearTimeout(timeout)
    if (err instanceof Error && err.name === 'AbortError') throw err
    // Network-level failure (backend down, CORS, DNS, etc.).
    throw new ApiError('Network request failed', 0)
  }
  clearTimeout(timeout)

  const text = await res.text()
  let data: unknown = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }

  if (!res.ok) {
    const detail =
      data && typeof data === 'object' && 'detail' in (data as any)
        ? String((data as any).detail)
        : typeof data === 'string'
          ? data
          : undefined
    throw new ApiError(`Request failed (${res.status})`, res.status, detail)
  }
  return data as T
}

// ---- Endpoint functions ----------------------------------------------------

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>('/health', { signal, timeoutMs: 8000 })
}

export function getDashboardSummary(
  signal?: AbortSignal,
): Promise<DashboardSummaryResponse> {
  return request<DashboardSummaryResponse>('/dashboard/summary', { signal })
}

export function getEvents(
  query?: EventQuery,
  signal?: AbortSignal,
): Promise<EventListResponse> {
  return request<EventListResponse>(`/events${buildQuery(query)}`, { signal })
}

export function getEvent(id: number, signal?: AbortSignal): Promise<EventResponse> {
  return request<EventResponse>(`/events/${id}`, { signal })
}

export function getTimeline(
  query?: TimelineQuery,
  signal?: AbortSignal,
): Promise<TimelineResponse> {
  return request<TimelineResponse>(`/timeline${buildQuery(query)}`, { signal })
}

export function investigate(
  payload: InvestigateRequest,
  signal?: AbortSignal,
): Promise<InvestigationResponse> {
  return request<InvestigationResponse>('/investigate', {
    method: 'POST',
    body: payload,
    timeoutMs: 120000,
    signal,
  })
}

export function generateReport(
  payload: ReportRequest,
  signal?: AbortSignal,
): Promise<InvestigationReportResponse> {
  return request<InvestigationReportResponse>('/reports/investigation', {
    method: 'POST',
    body: payload,
    timeoutMs: 120000,
    signal,
  })
}

export function generateReportText(
  payload: ReportRequest,
  signal?: AbortSignal,
): Promise<ReportTextResponse> {
  return request<ReportTextResponse>('/reports/investigation/text', {
    method: 'POST',
    body: payload,
    timeoutMs: 120000,
    signal,
  })
}

export function getIntegrity(signal?: AbortSignal): Promise<IntegrityResponse> {
  return request<IntegrityResponse>('/integrity', { signal })
}

export function getIncidents(signal?: AbortSignal): Promise<IncidentListResponse> {
  return request<IncidentListResponse>('/incidents', { signal })
}

export function getBehaviorAnomalies(
  query?: BehaviorQuery,
  signal?: AbortSignal,
): Promise<BehaviorResponse> {
  return request<BehaviorResponse>(`/behavior/anomalies${buildQuery(query)}`, {
    signal,
  })
}
