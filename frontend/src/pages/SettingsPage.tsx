import { useState } from 'react'
import { RotateCcw, Settings as SettingsIcon } from 'lucide-react'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/Button'
import { useSettings } from '@/hooks/useSettings'
import { cn } from '@/utils/cn'

const REFRESH_OPTIONS: { value: number; label: string }[] = [
  { value: 0, label: 'Manual' },
  { value: 15000, label: '15s' },
  { value: 30000, label: '30s' },
  { value: 60000, label: '1m' },
  { value: 300000, label: '5m' },
]

/** An accessible on/off switch. */
function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative h-6 w-11 shrink-0 rounded-full transition-colors',
        checked ? 'bg-brand' : 'bg-surface3',
      )}
    >
      <span
        className={cn(
          'absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform',
          checked ? 'left-0.5 translate-x-5' : 'left-0.5',
        )}
      />
    </button>
  )
}
/** A labelled settings row with a title, description and a control. */
function Row({
  title,
  description,
  control,
}: {
  title: string
  description: string
  control: React.ReactNode
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-t border-line-soft py-4 first:border-t-0 first:pt-0">
      <div className="min-w-0">
        <div className="text-sm font-medium text-fg">{title}</div>
        <p className="mt-0.5 text-xs leading-relaxed text-fg-muted">{description}</p>
      </div>
      <div className="shrink-0">{control}</div>
    </div>
  )
}

export function SettingsPage() {
  const { animationsEnabled, sidebarCollapsed, refreshIntervalMs, apiBase, update, reset } =
    useSettings()
  const [apiDraft, setApiDraft] = useState(apiBase)

  const applyApiBase = () => update({ apiBase: apiDraft.trim() })

  return (
    <div className="max-w-3xl space-y-5">
      <PageHeader
        title="Settings"
        description="Interface preferences for this browser."
        icon={<SettingsIcon className="h-5 w-5" />}
      />

      {/* These settings are purely client-side. */}
      <div className="rounded-card border border-line bg-surface/50 p-3.5 text-sm text-fg-muted">
        These preferences are stored in your browser only. They control the
        appearance and refresh cadence of this interface and never modify backend
        behavior or the evidence store.
      </div>
      <div className="fx-card p-5">
        <h3 className="mb-1 text-sm font-semibold uppercase tracking-wide text-fg-faint">
          Appearance
        </h3>
        <Row
          title="Animations"
          description="Enable subtle motion and transitions. Respects your system's reduced-motion setting."
          control={
            <Toggle
              label="Animations"
              checked={animationsEnabled}
              onChange={(v) => update({ animationsEnabled: v })}
            />
          }
        />
        <Row
          title="Collapse sidebar"
          description="Show the navigation as icons only on wide screens."
          control={
            <Toggle
              label="Collapse sidebar"
              checked={sidebarCollapsed}
              onChange={(v) => update({ sidebarCollapsed: v })}
            />
          }
        />
      </div>

      <div className="fx-card p-5">
        <h3 className="mb-1 text-sm font-semibold uppercase tracking-wide text-fg-faint">
          Data
        </h3>
        <Row
          title="Auto-refresh interval"
          description="How often pages poll the backend for new data. Manual disables polling."
          control={
            <div className="flex flex-wrap gap-1.5">
              {REFRESH_OPTIONS.map((o) => (
                <button
                  key={o.value}
                  type="button"
                  onClick={() => update({ refreshIntervalMs: o.value })}
                  className={cn(
                    'rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
                    refreshIntervalMs === o.value
                      ? 'border-brand/60 bg-brand/15 text-fg'
                      : 'border-line bg-surface2 text-fg-muted hover:text-fg',
                  )}
                >
                  {o.label}
                </button>
              ))}
            </div>
          }
        />
        <Row
          title="API base URL"
          description="Where the frontend sends requests. Leave as /api to use the built-in proxy."
          control={
            <div className="flex items-center gap-2">
              <input
                value={apiDraft}
                onChange={(e) => setApiDraft(e.target.value)}
                placeholder="/api"
                spellCheck={false}
                className="w-44 rounded-lg border border-line bg-surface2 px-3 py-1.5 font-mono text-xs text-fg placeholder:text-fg-faint focus:border-brand/50 focus-visible:outline-none"
              />
              <Button size="sm" variant="secondary" onClick={applyApiBase} disabled={apiDraft.trim() === apiBase}>
                Apply
              </Button>
            </div>
          }
        />
      </div>

      <div className="flex justify-end">
        <Button
          variant="ghost"
          icon={<RotateCcw className="h-4 w-4" />}
          onClick={() => {
            reset()
            setApiDraft('/api')
          }}
        >
          Reset to defaults
        </Button>
      </div>
    </div>
  )
}
