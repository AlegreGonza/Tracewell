import { type Stats } from '@/lib/api/schemas'
import { formatBytes, percent } from '@/lib/format'
import { HelpTip } from '@/components/help-tip'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const COLORS = ['--chart-1', '--chart-2', '--chart-3', '--chart-4', '--chart-5']

export function Protocols({ stats }: { stats: Stats }) {
  const rows = Object.entries(stats.by_protocol).sort(
    (a, b) => b[1].packets - a[1].packets
  )
  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1'>
          Distribución por protocolo <HelpTip topic='resumen' />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className='text-sm text-muted-foreground'>Sin sesiones.</p>
        ) : (
          <ul className='space-y-2'>
            {rows.map(([proto, p], i) => {
              const pct = percent(p.packets, stats.packets)
              return (
                <li key={proto} className='text-sm'>
                  <div className='flex justify-between gap-2'>
                    <span className='font-medium'>{proto}</span>
                    <span className='text-muted-foreground'>
                      {p.packets.toLocaleString('es-AR')} paquetes ·{' '}
                      {formatBytes(p.bytes)} · {pct.toFixed(1)} %
                    </span>
                  </div>
                  <div className='mt-1 h-2 rounded bg-muted' aria-hidden='true'>
                    <div
                      className='h-2 rounded'
                      style={{
                        width: `${pct}%`,
                        background: `var(${COLORS[i % COLORS.length]})`,
                      }}
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
