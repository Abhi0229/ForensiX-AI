import { useState } from 'react'
import { Search, Sparkles } from 'lucide-react'
import { Button } from './Button'
import { cn } from '@/utils/cn'

interface InvestigationInputProps {
  onSubmit: (question: string, useLlm: boolean) => void
  loading?: boolean
  className?: string
  initialQuestion?: string
}

const EXAMPLE_QUESTIONS = [
  'What suspicious activity happened recently?',
  'Were there any failed logon attempts?',
  'Show me USB device activity',
  'Was any malware detected by Defender?',
  'What files were recently modified?',
  'Are there any anomalous behaviors?',
]

/** The AI investigation prompt: a question box, example chips and an LLM toggle. */
export function InvestigationInput({
  onSubmit,
  loading,
  className,
  initialQuestion = '',
}: InvestigationInputProps) {
  const [question, setQuestion] = useState(initialQuestion)
  const [useLlm, setUseLlm] = useState(true)

  const submit = () => {
    const q = question.trim()
    if (!q || loading) return
    onSubmit(q, useLlm)
  }

  return (
    <div className={cn('fx-card p-5', className)}>
      <div className="relative">
        <textarea
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
              e.preventDefault()
              submit()
            }
          }}
          rows={3}
          placeholder="Ask a question about this endpoint's activity…"
          className="w-full resize-none rounded-lg border border-line bg-surface2 p-3.5 text-sm text-fg placeholder:text-fg-faint focus:border-brand/50 focus-visible:outline-none"
        />
      </div>

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
            Use AI narration
          </span>
        </label>

        <Button
          variant="primary"
          onClick={submit}
          loading={loading}
          disabled={!question.trim()}
          icon={!loading && <Search className="h-4 w-4" />}
        >
          Investigate
        </Button>
      </div>
      <p className="mt-2 text-[11px] text-fg-faint">
        Analysis is deterministic. AI narration only rephrases findings and
        degrades gracefully if the local model is unavailable.
      </p>
    </div>
  )
}
