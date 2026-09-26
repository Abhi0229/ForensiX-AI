import { useCallback, useRef, useState } from 'react'
import { FileText, Sparkles } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/Button'
import { ReportViewer } from '@/components/ReportViewer'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { SkeletonText, SkeletonCard } from '@/components/LoadingSkeleton'
import { generateReport, generateReportText, friendlyError } from '@/services/api'
import { cn } from '@/utils/cn'
import type { InvestigationReportResponse } from '@/types'

const EXAMPLE_QUESTIONS = [
  'Summarize all suspicious activity on this endpoint',
  'Investigate recent USB device usage',
  'Report on failed logon attempts',
  'What did Windows Defender detect?',
]

export function ReportsPage() {
  const [question, setQuestion] = useState('')
  const [useLlm, setUseLlm] = useState(true)
  const [report, setReport] = useState<InvestigationReportResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const lastArgs = useRef<{ question: string; use_llm: boolean } | null>(null)

  const run = useCallback(async (q: string, llm: boolean) => {
    const trimmed = q.trim()
    if (!trimmed) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    lastArgs.current = { question: trimmed, use_llm: llm }
    setLoading(true)
    setError(null)
    try {
      const res = await generateReport(lastArgs.current, controller.signal)
      setReport(res)
    } catch (err) {
      if (controller.signal.aborted) return
      setError(friendlyError(err))
    } finally {
      if (!controller.signal.aborted) setLoading(false)
    }
  }, [])
  // Download the deterministic .txt rendition of the same question.
  const download = useCallback(async () => {
    if (!lastArgs.current) return
    setDownloading(true)
    try {
      const res = await generateReportText(lastArgs.current)
      const blob = new Blob([res.text], { type: 'text/plain;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${res.report_id || 'forensix-report'}.txt`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch {
      /* Ignore download failures — the on-screen report remains available. */
    } finally {
      setDownloading(false)
    }
  }, [])

  const submit = () => run(question, useLlm)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigation Reports"
        description="Generate a structured, court-style report from a plain-language question."
        icon={<FileText className="h-5 w-5" />}
      />

      {/* Report composer */}
      <div className="fx-card p-5 print:hidden">
        <label htmlFor="report-q" className="text-sm font-medium text-fg">
          Report question
        </label>
        <textarea
          id="report-q"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
              e.preventDefault()
              submit()
            }
          }}
          rows={3}
          placeholder="Describe what the report should cover…"
          className="mt-2 w-full resize-none rounded-lg border border-line bg-surface2 p-3.5 text-sm text-fg placeholder:text-fg-faint focus:border-brand/50 focus-visible:outline-none"
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {EXAMPLE_QUESTIONS.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => setQuestion(q)}
              className="rounded-full border border-line bg-surface2 px-3 py-1 text-xs text-fg-muted transition-colors hover:border-brand/40 hover:text-fg"
            >
              {q}
            </button>
          ))}
        </div>

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-fg-muted">
            <button
              type="button"
              role="switch"
              aria-checked={useLlm}
              onClick={() => setUseLlm((v) => !v)}
              className={cn(
                'relative h-5 w-9 rounded-full transition-colors',
                useLlm ? 'bg-brand' : 'bg-surface3',
              )}
            >
              <span
                className={cn(
                  'absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform',
                  useLlm ? 'left-0.5 translate-x-4' : 'left-0.5',
                )}
              />
            </button>
            <span className="inline-flex items-center gap-1">
              <Sparkles className="h-3.5 w-3.5" />
              Include AI narrative
            </span>
          </label>
          <Button
            variant="primary"
            onClick={submit}
            loading={loading}
            disabled={!question.trim()}
            icon={!loading && <FileText className="h-4 w-4" />}
          >
            Generate report
          </Button>
        </div>
        <p className="mt-2 text-[11px] text-fg-faint">
          Report findings are deterministic. The AI narrative, when enabled, only
          rephrases those findings and is omitted if the local model is unavailable.
        </p>
      </div>
      {loading ? (
        <div className="space-y-4">
          <div className="fx-card p-6">
            <SkeletonText lines={5} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <SkeletonCard />
            <SkeletonCard />
          </div>
        </div>
      ) : error ? (
        <ErrorState
          message={error}
          onRetry={
            lastArgs.current
              ? () => run(lastArgs.current!.question, lastArgs.current!.use_llm)
              : undefined
          }
        />
      ) : report ? (
        <ReportViewer report={report} onDownload={download} downloading={downloading} />
      ) : (
        <EmptyState
          icon={FileText}
          title="No report generated yet"
          message="Enter a question above to compile a structured investigation report from the collected evidence."
        />
      )}
    </div>
  )
}
