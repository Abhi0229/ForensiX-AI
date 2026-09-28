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
import { useChartTheme } from '@/hooks/useChartTheme'

interface SourceBarProps {
  data: Record<string, number>
  height?: number
}

/** A horizontal bar chart of event counts by source. */
export function SourceBar({ data, height = 260 }: SourceBarProps) {
  const ct = useChartTheme()
  const axis = { fontSize: 11, fill: ct.axis }
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
        <CartesianGrid horizontal={false} stroke={ct.grid} />
        <XAxis type="number" tick={axis} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          tick={axis}
          axisLine={false}
          tickLine={false}
          width={130}
        />
        <Tooltip
          cursor={{ fill: ct.cursor }}
          contentStyle={{
            background: ct.tooltipBg,
            border: `1px solid ${ct.tooltipBorder}`,
            borderRadius: 10,
            fontSize: 12,
          }}
          labelStyle={{ color: ct.tooltipLabel }}
          itemStyle={{ color: ct.tooltipItem }}
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
