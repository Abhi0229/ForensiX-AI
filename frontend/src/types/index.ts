/**
 * ForensiX AI — API type definitions.
 *
 * These interfaces mirror the Phase 14 FastAPI response schemas
 * (backend/api/schemas.py). They describe untrusted backend data:
 * every string is rendered as text, never as HTML.
 */

// ---- Shared primitives -----------------------------------------------------

/** Backend severity labels (case as emitted by the API). */
export type Severity =
  | 'INFO'
  | 'LOW'
  | 'WARNING'
  | 'MEDIUM'
  | 'ERROR'
  | 'HIGH'
  | 'CRITICAL'
  | 'AUDIT_SUCCESS'
  | 'AUDIT_FAILURE'
  | string

/** Behavioral classification states. */
export type BehaviorClassification =
  | 'NORMAL'
  | 'SUSPICIOUS'
  | 'ANOMALOUS'
  | 'INSUFFICIENT_HISTORY'
  | string

/** Integrity chain states. */
export type IntegrityStatus =
  | 'VERIFIED'
  | 'LEGACY'
  | 'TAMPERED'
  | 'UNVERIFIED'
  | string

/** A loosely-typed metadata bag as returned by the backend. */
export type MetadataBag = Record<string, unknown> | null

// ---- Events ----------------------------------------------------------------

export interface EventResponse {
  id: number
  timestamp: string | null
  source: string | null
  event_type: string | null
  description: string | null
  severity: Severity | null
  user: string | null
  device: string | null
  file_path: string | null
  metadata: MetadataBag
}

export interface EventListResponse {
  events: EventResponse[]
  total: number
  limit: number
  offset: number
}

export interface TimelineResponse {
  events: EventResponse[]
  total: number
  limit: number
  offset: number
}

// ---- Investigation ---------------------------------------------------------

export interface EvidenceItem {
  id?: number
  timestamp?: string | null
  source?: string | null
  event_type?: string | null
  description?: string | null
  severity?: Severity | null
  user?: string | null
  device?: string | null
  file_path?: string | null
  relevance?: string | null
  [key: string]: unknown
}

export interface InvestigationResponse {
  question: string
  answer: string | null
  answer_source: string | null
  message: string | null
  llm_available: boolean
  llm_model: string | null
  deterministic_summary: string | null
  context: Record<string, unknown> | null
  evidence: EvidenceItem[]
  evidence_count: number
  candidate_incidents: IncidentResponse[]
  behavioral_anomalies: BehaviorAnomalyResponse[]
  behavioral_baseline_status: string | null
  integrity: IntegrityResponse | null
  warnings: string[]
}

// ---- Incidents (candidate incidents) --------------------------------------

export interface IncidentResponse {
  incident_id: string
  start_time: string | null
  end_time: string | null
  event_ids: number[]
  sources: string[]
  event_types: string[]
  correlation_reasons: string[]
  priority: string | null
  confidence_score: number | null
  confidence_signals: string[]
  integrity_summary: Record<string, unknown> | null
  events: EventResponse[]
}

export interface IncidentListResponse {
  candidate_incidents: IncidentResponse[]
  total: number
  terminology: string | null
  note: string | null
}

// ---- Behavior analysis -----------------------------------------------------

export interface AnomalyEventRef {
  event_id: number
  timestamp: string | null
  source: string | null
  event_type: string | null
  severity: Severity | null
  user: string | null
  device: string | null
  file_path: string | null
  category: string | null
  hour: number | null
  weekday: number | null
}

export interface BehaviorAnomalyResponse {
  anomaly_score: number | null
  classification: BehaviorClassification
  severity: Severity | null
  reasons: string[]
  signals: Record<string, unknown> | null
  baseline_status: string | null
  event: AnomalyEventRef
}

export interface BehaviorCounts {
  NORMAL: number
  SUSPICIOUS: number
  ANOMALOUS: number
  INSUFFICIENT_HISTORY: number
  [key: string]: number
}

export interface BehaviorResponse {
  baseline_status: string | null
  counts: BehaviorCounts
  total_evaluated: number
  anomalies: BehaviorAnomalyResponse[]
  disclaimer: string | null
}

// ---- Integrity -------------------------------------------------------------

export interface IntegrityResponse {
  valid: boolean
  status: IntegrityStatus
  total_events: number
  checked_events: number
  hashed_events: number
  legacy_events: number
  invalid_events: number
  errors: string[]
}

// ---- Reports ---------------------------------------------------------------

export interface InvestigationReportResponse {
  report_id: string
  generated_at: string | null
  original_question: string | null
  executive_summary: string | null
  incident_summary: Record<string, unknown> | null
  timeline: Array<Record<string, unknown>>
  evidence: EvidenceItem[]
  correlation_findings: Array<Record<string, unknown>>
  behavioral_findings: Array<Record<string, unknown>>
  integrity_status: IntegrityResponse | Record<string, unknown> | null
  warnings: string[]
  limitations: string[]
  conclusion: string | null
  metadata: Record<string, unknown> | null
  llm_narrative: string | null
  llm_available: boolean
  llm_error: string | null
}

export interface ReportTextResponse {
  report_id: string
  text: string
}

// ---- Dashboard -------------------------------------------------------------

export interface DashboardCapabilities {
  investigation_available: boolean
  report_available: boolean
  correlation_available: boolean
  behavior_available: boolean
  integrity_available: boolean
}

export interface DashboardSummaryResponse {
  total_events: number
  events_by_source: Record<string, number>
  events_by_severity: Record<string, number>
  recent_events: EventResponse[]
  candidate_incident_count: number
  behavioral_anomaly_count: number
  integrity: IntegrityResponse | null
  latest_event_timestamp: string | null
  capabilities: DashboardCapabilities
}

// ---- Health ----------------------------------------------------------------

export interface HealthResponse {
  status: string
  service?: string
  version?: string
  [key: string]: unknown
}

// ---- Request parameters ----------------------------------------------------

export interface EventQuery {
  limit?: number
  offset?: number
  source?: string
  severity?: string
  event_type?: string
  user?: string
  device?: string
  search?: string
  start_time?: string
  end_time?: string
}

export interface TimelineQuery {
  limit?: number
  offset?: number
  source?: string
  severity?: string
  start_time?: string
  end_time?: string
}

export interface InvestigateRequest {
  question: string
  limit?: number
  use_llm?: boolean
}

export interface ReportRequest {
  question: string
  use_llm?: boolean
}

export interface BehaviorQuery {
  limit?: number
}
