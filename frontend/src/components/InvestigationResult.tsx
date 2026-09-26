import { AlertTriangle, Bot, Cpu, ShieldQuestion } from 'lucide-react'
import { Badge } from './Badge'
import { EvidenceList } from './EvidenceList'
import { IncidentCard } from './IncidentCard'
import { AnomalyCard } from './AnomalyCard'
import { IntegrityStatus } from './IntegrityStatus'
import type { EventResponse, InvestigationResponse } from '@/types'
import { cn } from '@/utils/cn'

interface InvestigationResultProps {
  result: InvestigationResponse
  onSelectEventId?: (id: number) => void
  onSelectEvent?: (event: EventResponse) => void
  className?: string
}

function SectionTitle({ children, count }: { children: string; count?: number }) {
  return (
    <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-fg">
      {children}
      {typeof count === 'number' && (
        <span className="rounded-full bg-surface3 px-1.5 py-0.5 text-[11px] text-fg-faint">
          {count}
        </span>
      )}
    </h3>
  )
}

/** Renders a full deterministic investigation result with optional AI narration. */
export function InvestigationResult({
  result,
  onSelectEventId,
  onSelectEvent,
  className,
}: InvestigationResultProps) {
  const isLlm = (result.answer_source || '').toLowerCase().includes('llm')
  const answerText = result.answer || result.deterministic_summary || result.message

  return (
    <div className={cn('space-y-6', className)}>
      {/* Answer */}
      <div className="fx-card p-5">
        <div className="flex items-center justify-between gap-3">
          <SectionTitle>Answer</SectionTitle>
          <Badge
            className={
              isLlm
                ? 'text-violet bg-violet/10 border-violet/30'
                : 'text-cyan bg-cyan/10 border-cyan/30'
            }
            dotClassName={isLlm ? 'bg-violet' : 'bg-cyan'}
          >
            <span className="inline-flex items-center gap-1">
              {isLlm ? <Bot className="h-3 w-3" /> : <Cpu className="h-3 w-3" />}
              {isLlm ? 'AI narration' : 'Deterministic'}
            </span>
          </Badge>
        </div>
        {/* Rendered as plain text — backend/LLM content is never treated as HTML. */}
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">
          {answerText || 'No answer was produced for this question.'}
        </p>
        {!result.llm_available && (
          <p className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface2 px-3 py-1.5 text-xs text-fg-faint">
            <ShieldQuestion className="h-3.5 w-3.5" />
            Local AI model unavailable — showing deterministic findings only.
          </p>
        )}
      </div>

      {/* Warnings */}
      {result.warnings?.length > 0 && (
        <div className="rounded-card border border-sev-warning/30 bg-sev-warning/5 p-4">
          <p className="mb-2 flex items-center gap-2 text-sm font-medium text-sev-warning">
            <AlertTriangle className="h-4 w-4" /> Warnings
          </p>
          <ul className="space-y-1">
            {result.warnings.map((w, i) => (
              <li key={i} className="text-sm text-fg-muted">
                {w}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Evidence */}
      {result.evidence?.length > 0 && (
        <section>
          <SectionTitle count={result.evidence_count ?? result.evidence.length}>
            Supporting evidence
          </SectionTitle>
          <EvidenceList evidence={result.evidence} onSelect={onSelectEventId} />
        </section>
      )}

      {/* Candidate incidents */}
      {result.candidate_incidents?.length > 0 && (
        <section>
          <SectionTitle count={result.candidate_incidents.length}>
            Candidate incidents
          </SectionTitle>
          <div className="space-y-3">
            {result.candidate_incidents.map((inc) => (
              <IncidentCard
                key={inc.incident_id}
                incident={inc}
                onSelectEvent={onSelectEvent}
              />
            ))}
          </div>
        </section>
      )}

      {/* Behavioral anomalies */}
      {result.behavioral_anomalies?.length > 0 && (
        <section>
          <SectionTitle count={result.behavioral_anomalies.length}>
            Behavioral anomalies
          </SectionTitle>
          <div className="grid gap-3 lg:grid-cols-2">
            {result.behavioral_anomalies.map((a, i) => (
              <AnomalyCard key={a.event?.event_id ?? i} anomaly={a} />
            ))}
          </div>
        </section>
      )}

      {/* Integrity */}
      {result.integrity && (
        <section>
          <SectionTitle>Evidence integrity</SectionTitle>
          <IntegrityStatus integrity={result.integrity} detailed />
        </section>
      )}
    </div>
  )
}
