import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { EmptyState } from '../EmptyState'
import { CHART_PALETTE } from '@/utils/severity'

interface SourceBarProps {
  data: Record<string, number>
  height?: number
}

const AXIS = { fontSize: 11, fill: '#61708a' }

/** A horizontal bar chart of event counts by source. */
export function SourceBar({ data, height = 260 }: SourceBarProps) {
  const entries = Object.entries(data || {})
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 10)

  if (entries.length === 0) {
    return <EmptyState title="No source data" message="No events have been recorded yet." />
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={entries} layout="vertical" margin={{ left: 8, right: 16 }}>
        <CartesianGrid horizontal={false} stroke="#1a2233" />
        <XAxis type="number" tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          tick={AXIS}
          axisLine={false}
          tickLine={false}
          width={130}
        />
        <Tooltip
          cursor={{ fill: 'rgba(255,255,255,0.03)' }}
          contentStyle={{
            background: '#0f1521',
            border: '1px solid #212c40',
            borderRadius: 10,
            fontSize: 12,
          }}
          labelStyle={{ color: '#e7edf7' }}
          itemStyle={{ color: '#93a1b8' }}
        />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} maxBarSize={22}>
          {entries.map((e, i) => (
            <Cell key={e.name} fill={CHART_PALETTE[i % CHART_PALETTE.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
