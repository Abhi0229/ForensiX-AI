import { Download, FileText, Printer } from 'lucide-react'
import { Button } from './Button'
import { EvidenceList } from './EvidenceList'
import { IntegrityStatus } from './IntegrityStatus'
import type { InvestigationReportResponse, IntegrityResponse } from '@/types'
import { cn } from '@/utils/cn'
import { displayValue, formatDateTime, humanize, NOT_AVAILABLE } from '@/utils/format'

interface ReportViewerProps {
  report: InvestigationReportResponse
  onDownload?: () => void
  downloading?: boolean
  className?: string
}

function Section({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <section className="border-t border-line-soft py-5 first:border-t-0 first:pt-0">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-fg-faint">
        {title}
      </h3>
      {children}
    </section>
  )
}

/** Render an unknown record as a compact definition list of primitive fields. */
function RecordRows({ record }: { record: Record<string, unknown> }) {
  const entries = Object.entries(record).filter(
    ([, v]) => v !== null && v !== undefined && typeof v !== 'object',
  )
  if (entries.length === 0) {
    return <p className="text-sm text-fg-faint">{NOT_AVAILABLE}</p>
  }
  return (
    <dl className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
      {entries.map(([k, v]) => (
        <div key={k} className="flex gap-2 text-sm">
          <dt className="text-fg-faint">{humanize(k)}:</dt>
          <dd className="text-fg">{displayValue(v)}</dd>
        </div>
      ))}
    </dl>
  )
}

export function ReportViewer({
  report,
  onDownload,
  downloading,
  className,
}: ReportViewerProps) {
  const integrity = report.integrity_status as IntegrityResponse | null
  const hasIntegrity =
    integrity && typeof integrity === 'object' && 'status' in integrity

  return (
    <div className={cn('fx-card', className)}>
      {/* Report header — print-friendly */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line px-6 py-5">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-surface2 text-brand">
            <FileText className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-fg">Investigation Report</h2>
            <p className="mt-0.5 font-mono text-xs text-fg-faint">
              {report.report_id} · {formatDateTime(report.generated_at)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 print:hidden">
          <Button variant="secondary" size="sm" icon={<Printer className="h-4 w-4" />} onClick={() => window.print()}>
            Print
          </Button>
          {onDownload && (
            <Button
              variant="primary"
              size="sm"
              icon={<Download className="h-4 w-4" />}
              onClick={onDownload}
              loading={downloading}
            >
              Download .txt
            </Button>
          )}
        </div>
      </div>

      <div className="px-6 py-2">
        {report.original_question && (
          <Section title="Question">
            <p className="text-sm text-fg">{report.original_question}</p>
          </Section>
        )}

        {report.executive_summary && (
          <Section title="Executive summary">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">
              {report.executive_summary}
            </p>
          </Section>
        )}

        {report.llm_narrative && (
          <Section title="AI narrative">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">
              {report.llm_narrative}
            </p>
          </Section>
        )}

        {report.incident_summary && Object.keys(report.incident_summary).length > 0 && (
          <Section title="Incident summary">
            <RecordRows record={report.incident_summary} />
          </Section>
        )}

        {report.correlation_findings?.length > 0 && (
          <Section title="Correlation findings">
            <div className="space-y-3">
              {report.correlation_findings.map((f, i) => (
                <div key={i} className="rounded-lg border border-line bg-surface2 p-3">
                  <RecordRows record={f} />
                </div>
              ))}
            </div>
          </Section>
        )}

        {report.behavioral_findings?.length > 0 && (
          <Section title="Behavioral findings">
            <div className="space-y-3">
              {report.behavioral_findings.map((f, i) => (
                <div key={i} className="rounded-lg border border-line bg-surface2 p-3">
                  <RecordRows record={f} />
                </div>
              ))}
            </div>
          </Section>
        )}

        {report.timeline?.length > 0 && (
          <Section title="Timeline">
            <ol className="space-y-2">
              {report.timeline.map((entry, i) => (
                <li key={i} className="rounded-lg border border-line bg-surface2 p-3">
                  <RecordRows record={entry} />
                </li>
              ))}
            </ol>
          </Section>
        )}

        {report.evidence?.length > 0 && (
          <Section title="Evidence">
            <EvidenceList evidence={report.evidence} />
          </Section>
        )}

        {hasIntegrity && (
          <Section title="Evidence integrity">
            <IntegrityStatus integrity={integrity as IntegrityResponse} detailed />
          </Section>
        )}

        {report.warnings?.length > 0 && (
          <Section title="Warnings">
            <ul className="space-y-1">
              {report.warnings.map((w, i) => (
                <li key={i} className="text-sm text-sev-warning">
                  {w}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {report.limitations?.length > 0 && (
          <Section title="Limitations">
            <ul className="space-y-1">
              {report.limitations.map((l, i) => (
                <li key={i} className="flex gap-2 text-sm text-fg-muted">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-fg-faint" />
                  {l}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {report.conclusion && (
          <Section title="Conclusion">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-fg-muted">
              {report.conclusion}
            </p>
          </Section>
        )}
      </div>
    </div>
  )
}
