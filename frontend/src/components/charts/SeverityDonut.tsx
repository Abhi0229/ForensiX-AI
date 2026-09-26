import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { EmptyState } from '../EmptyState'
import { humanize } from '@/utils/format'
import { severityHex } from '@/utils/severity'

interface SeverityDonutProps {
  data: Record<string, number>
  height?: number
}

/** A donut chart of event counts by severity. */
export function SeverityDonut({ data, height = 240 }: SeverityDonutProps) {
  const entries = Object.entries(data || {})
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: humanize(k), key: k, value: v }))
    .sort((a, b) => b.value - a.value)

  if (entries.length === 0) {
    return <EmptyState title="No severity data" message="No events have been recorded yet." />
  }

  const total = entries.reduce((sum, e) => sum + e.value, 0)

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row">
      <div className="relative" style={{ width: height, height }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={entries}
              dataKey="value"
              nameKey="name"
              innerRadius="62%"
              outerRadius="100%"
              paddingAngle={2}
              stroke="none"
            >
              {entries.map((e) => (
                <Cell key={e.key} fill={severityHex(e.key)} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#0f1521',
                border: '1px solid #212c40',
                borderRadius: 10,
                fontSize: 12,
              }}
              labelStyle={{ color: '#e7edf7' }}
              itemStyle={{ color: '#93a1b8' }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-fg">{total}</span>
          <span className="text-[11px] uppercase tracking-wide text-fg-faint">events</span>
        </div>
      </div>
      <ul className="flex-1 space-y-1.5">
        {entries.map((e) => (
          <li key={e.key} className="flex items-center justify-between gap-3 text-sm">
            <span className="inline-flex items-center gap-2 text-fg-muted">
              <span
                className="h-2.5 w-2.5 rounded-sm"
                style={{ background: severityHex(e.key) }}
              />
              {e.name}
            </span>
            <span className="tabular-nums text-fg">{e.value}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
