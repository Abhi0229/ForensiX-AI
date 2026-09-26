import { Badge } from './Badge'
import { cn } from '@/utils/cn'
import { severityTone } from '@/utils/severity'
import { humanize } from '@/utils/format'

interface SeverityBadgeProps {
  severity?: string | null
  className?: string
}

/**
 * A severity pill with a color-coded dot. Never relies on color alone —
 * the label text always communicates the severity.
 */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const tone = severityTone(severity)
  const label = severity ? humanize(severity) : 'Unknown'
  return (
    <Badge
      className={cn(tone.text, tone.bg, tone.border, className)}
      dotClassName={tone.dot}
      title={`Severity: ${label}`}
    >
      {label}
    </Badge>
  )
}
