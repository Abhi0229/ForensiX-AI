import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, Sparkles } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { InvestigationInput } from '@/components/InvestigationInput'
import { InvestigationResult } from '@/components/InvestigationResult'
import { EventDetailsPanel } from '@/components/EventDetailsPanel'
import { EmptyState } from '@/components/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { SkeletonText, SkeletonCard } from '@/components/LoadingSkeleton'
import { getEvent, investigate } from '@/services/api'
import { friendlyError } from '@/services/api'
import type { EventResponse, InvestigationResponse } from '@/types'

export function InvestigatePage() {
  const [params] = useSearchParams()
  const initialQuestion = params.get('q') ?? ''

  const [result, setResult] = useState<InvestigationResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<EventResponse | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const lastArgs = useRef<{ q: string; llm: boolean } | null>(null)

  const run = useCallback(async (question: string, useLlm: boolean) => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    lastArgs.current = { q: question, llm: useLlm }
    setLoading(true)
    setError(null)
    try {
      const res = await investigate({ question, use_llm: useLlm }, controller.signal)
      setResult(res)
    } catch (err) {
      if (controller.signal.aborted) return
      setError(friendlyError(err))
    } finally {
      if (!controller.signal.aborted) setLoading(false)
    }
  }, [])

  // Auto-run when arriving with a ?q= query from the global search bar.
  const autoRan = useRef(false)
  useEffect(() => {
    if (initialQuestion && !autoRan.current) {
      autoRan.current = true
      run(initialQuestion, true)
    }
  }, [initialQuestion, run])

  const openEventById = useCallback(async (id: number) => {
    try {
      const event = await getEvent(id)
      setSelected(event)
    } catch {
      /* ignore — the event may no longer be available */
    }
  }, [])

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Investigation"
        description="Ask a question in plain language. Findings are deterministic; AI only narrates them."
        icon={<Search className="h-5 w-5" />}
      />

      <InvestigationInput
        onSubmit={run}
        loading={loading}
        initialQuestion={initialQuestion}
      />

      {loading ? (
        <div className="space-y-4">
          <div className="fx-card p-5">
            <SkeletonText lines={4} />
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
              ? () => run(lastArgs.current!.q, lastArgs.current!.llm)
              : undefined
          }
        />
      ) : result ? (
        <InvestigationResult
          result={result}
          onSelectEventId={openEventById}
          onSelectEvent={setSelected}
        />
      ) : (
        <EmptyState
          icon={Sparkles}
          title="Start an investigation"
          message="Ask a question above or pick one of the suggested prompts to analyze this endpoint's activity."
        />
      )}

      <EventDetailsPanel
        event={selected}
        open={selected !== null}
        onClose={() => setSelected(null)}
        onSelectRelated={setSelected}
      />
    </div>
  )
}
