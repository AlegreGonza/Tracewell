import { useState } from 'react'
import { useTimeline } from '@/lib/api/queries'
import { formatDuration, formatTime } from '@/lib/format'
import { HelpTip } from '@/components/help-tip'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

type Metric = 'packets' | 'bytes'

export function Activity() {
  const { data } = useTimeline()
  const [metric, setMetric] = useState<Metric>('packets')
  if (!data || data.packets.length === 0) return null

  const chosen = data[metric]
  const values = chosen.length === data.packets.length ? chosen : data.packets
  const max = Math.max(...values, 1)
  const peak = values.indexOf(Math.max(...values))
  const unit = metric === 'bytes' ? 'bytes' : 'paquetes'
  const at = (i: number) =>
    formatTime((data.start ?? 0) + i * data.bucket_seconds)
  const summary = `Tráfico en el tiempo: ${values.length} intervalos de ${formatDuration(data.bucket_seconds)}. Pico de ${values[peak].toLocaleString('es-AR')} ${unit} a las ${at(peak)}.`

  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1'>
          Tráfico en el tiempo <HelpTip topic='tiempo' />
        </CardTitle>
        <label className='ms-auto flex items-center gap-2 text-sm'>
          <span className='text-muted-foreground'>Mostrar</span>
          <select
            className='h-8 rounded-md border border-input bg-background px-2 text-sm'
            value={metric}
            onChange={(e) => setMetric(e.target.value as Metric)}
          >
            <option value='packets'>Paquetes</option>
            <option value='bytes'>Bytes</option>
          </select>
        </label>
      </CardHeader>
      <CardContent>
        <div
          role='img'
          aria-label={summary}
          className='flex h-40 items-end gap-px border-b'
        >
          {values.map((v, i) => (
            <div
              key={i}
              title={`${at(i)}: ${v.toLocaleString('es-AR')} ${unit}`}
              className='min-w-px flex-1 rounded-t'
              style={{
                height: `${Math.max((v / max) * 100, 1)}%`,
                background: `var(${i === peak ? '--chart-3' : '--chart-1'})`,
              }}
            />
          ))}
        </div>
        <p className='mt-1 flex justify-between font-mono text-xs text-muted-foreground'>
          <span>{at(0)}</span>
          <span>cada barra = {formatDuration(data.bucket_seconds)}</span>
          <span>{at(values.length - 1)}</span>
        </p>
        <p className='mt-2 text-sm text-muted-foreground'>{summary}</p>
      </CardContent>
    </Card>
  )
}
