import { useMemo } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { EmptyState } from '../EmptyState'
import type { EventResponse } from '@/types'
import { parseDate } from '@/utils/format'

interface ActivityAreaProps {
  events: EventResponse[]
  height?: number
}

const AXIS = { fontSize: 11, fill: '#61708a' }

/** Buckets events into ~24 time slots between the earliest and latest event. */
function bucketEvents(events: EventResponse[]) {
  const times = events
    .map((e) => parseDate(e.timestamp)?.getTime())
    .filter((t): t is number => typeof t === 'number')
    .sort((a, b) => a - b)
  if (times.length === 0) return []

  const min = times[0]
  const max = times[times.length - 1]
  const span = Math.max(max - min, 1)
  const bucketCount = Math.min(24, Math.max(6, times.length))
  const size = span / bucketCount

  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    t: min + i * size,
    count: 0,
  }))
  for (const t of times) {
    const idx = Math.min(bucketCount - 1, Math.floor((t - min) / size))
    buckets[idx].count += 1
  }

  const sameDay = max - min < 86400000
  return buckets.map((b) => ({
    label: new Date(b.t).toLocaleString(undefined, sameDay
      ? { hour: '2-digit', minute: '2-digit' }
      : { month: 'short', day: 'numeric' }),
    count: b.count,
  }))
}

/** An area chart of event volume over time, derived from real event timestamps. */
export function ActivityArea({ events, height = 260 }: ActivityAreaProps) {
  const data = useMemo(() => bucketEvents(events), [events])

  if (data.length === 0) {
    return <EmptyState title="No activity data" message="No timestamped events are available yet." />
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ left: -12, right: 8, top: 8 }}>
        <defs>
          <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4c8dff" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#4c8dff" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="#1a2233" />
        <XAxis dataKey="label" tick={AXIS} axisLine={false} tickLine={false} minTickGap={24} />
        <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} width={36} />
        <Tooltip
          cursor={{ stroke: '#212c40' }}
          contentStyle={{
            background: '#0f1521',
            border: '1px solid #212c40',
            borderRadius: 10,
            fontSize: 12,
          }}
          labelStyle={{ color: '#e7edf7' }}
          itemStyle={{ color: '#93a1b8' }}
        />
        <Area
          type="monotone"
          dataKey="count"
          name="Events"
          stroke="#4c8dff"
          strokeWidth={2}
          fill="url(#activityFill)"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
