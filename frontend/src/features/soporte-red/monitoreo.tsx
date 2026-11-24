import { useState } from 'react'
import {
  useMonitorClear,
  useMonitorStart,
  useMonitorStop,
} from '@/lib/api/mutations'
import { useMonitorStatus } from '@/lib/api/queries'
import { formatDuration } from '@/lib/format'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { QueryBoundary } from '@/components/query-boundary'
import { Box, Dash, Fact, Facts, Verdict } from './components/parts'
import { monitorExtra, view } from './views'

const when = (epoch: number) =>
  Number.isFinite(epoch)
    ? new Date(epoch * 1000).toLocaleTimeString('es-AR')
    : '—'

const LAYER_TEXT: Record<string, string> = {
  'red local': 'No llegaba al router (red local o Wi-Fi)',
  internet: 'El router respondía pero no había salida a Internet',
  dns: 'Había Internet pero fallaba el DNS',
}

type Sample = { ms?: number | null; layer?: string | null }

// Una barra por medición: la altura es la latencia; en rojo, las veces que algo falló.
function Spark({ samples }: { samples: Sample[] }) {
  if (samples.length === 0) return null
  const max = Math.max(...samples.map((s) => s.ms ?? 0), 50)
  return (
    <div
      role='img'
      aria-label={`Últimas ${samples.length} mediciones`}
      className='flex h-16 items-end gap-px'
    >
      {samples.map((s, i) => (
        <i
          key={i}
          title={s.layer ? `Falla: ${s.layer}` : `${s.ms} ms`}
          className={`min-w-0.5 flex-1 rounded-sm ${s.layer ? 'bg-destructive' : 'bg-chart-2'}`}
          style={{
            height: s.layer
              ? '100%'
              : `${Math.max(6, ((s.ms ?? 0) / max) * 100)}%`,
          }}
        />
      ))}
    </div>
  )
}

function currentText(current: string | null | undefined) {
  if (current === 'ok') return 'Ahora: todo funciona'
  if (!current || current === 'sin datos')
    return 'Esperando la primera medición…'
  return `Ahora: falla (${current})`
}

/** «Monitoreo de cortes»: mide cada pocos segundos y registra los cortes. */
export function Monitoreo() {
  const [every, setEvery] = useState(2)
  const q = useMonitorStatus({
    refetchInterval: (query) => (query.state.data?.running ? 2000 : false),
  })
  const start = useMonitorStart()
  const stop = useMonitorStop()
  const clear = useMonitorClear()
  const busy = start.isPending || stop.isPending || clear.isPending

  return (
    <Box
      title='Monitoreo de cortes'
      topic='soporte_monitoreo'
      actions={
        <span className='text-sm text-muted-foreground'>
          {q.data?.running ? 'midiendo…' : 'detenido'}
        </span>
      }
    >
      <QueryBoundary query={q}>
        {(s) => {
          const x = view(monitorExtra, s)
          return (
            <>
              <div className='flex flex-wrap items-end gap-3'>
                {s.running ? (
                  <Button
                    disabled={busy}
                    onClick={() => stop.mutate(undefined)}
                  >
                    Detener
                  </Button>
                ) : (
                  <>
                    <label className='space-y-1.5 text-sm'>
                      <span className='block'>Medir cada</span>
                      <select
                        value={every}
                        onChange={(e) => setEvery(Number(e.target.value))}
                        className='h-9 rounded-md border bg-background px-2'
                      >
                        {[1, 2, 5, 10].map((n) => (
                          <option key={n} value={n}>
                            {n} s
                          </option>
                        ))}
                      </select>
                    </label>
                    <Button disabled={busy} onClick={() => start.mutate(every)}>
                      Empezar a monitorear
                    </Button>
                  </>
                )}
                <Button
                  variant='outline'
                  disabled={busy || s.total === 0}
                  onClick={() => clear.mutate(undefined)}
                >
                  Borrar registro
                </Button>
              </div>
              <p className='text-sm text-muted-foreground'>
                Solo mide mientras Tracewell está abierto; lo registrado se
                pierde al cerrarlo. Hace un ping a tu router y abre conexiones
                cortas a 1.1.1.1 y a sitios conocidos.
              </p>
              {s.total === 0 && !s.running && (
                <p className='text-sm text-muted-foreground'>
                  Apretá «Empezar a monitorear» y dejá Tracewell abierto
                  mientras trabajás.
                </p>
              )}
              {s.total > 0 && (
                <>
                  <Verdict ok={s.current === 'ok'}>
                    <p className='font-semibold'>{currentText(s.current)}</p>
                  </Verdict>
                  <Facts>
                    <Fact label='Disponibilidad'>
                      {s.availability_pct ?? '—'} % de {s.total} mediciones
                    </Fact>
                    <Fact label='Cortes registrados'>
                      {s.outage_count} ({formatDuration(s.downtime_seconds)} en
                      total)
                    </Fact>
                    <Fact label='Latencia a Internet'>
                      {s.latency?.last != null
                        ? `${s.latency.last} ms (promedio ${s.latency.avg ?? '—'}, máximo ${s.latency.max ?? '—'})`
                        : '—'}
                    </Fact>
                    {x?.wifi?.signal != null && (
                      <Fact label='Señal Wi-Fi'>
                        {x.wifi.signal} % ({x.wifi.ssid ?? '?'})
                      </Fact>
                    )}
                    <Fact label='Router medido' mono>
                      {x?.gateway ?? 'no se encontró'}
                    </Fact>
                  </Facts>
                  <Spark samples={x?.samples ?? []} />
                  <h3 className='font-medium'>Cronología de cortes</h3>
                  {!x?.outages.length ? (
                    <p className='text-sm text-muted-foreground'>
                      Sin cortes por ahora.
                    </p>
                  ) : (
                    <div className='overflow-x-auto rounded-md border'>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Empezó</TableHead>
                            <TableHead>Duró</TableHead>
                            <TableHead>Qué falló</TableHead>
                            <TableHead>Señal Wi-Fi al empezar</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {x.outages.map((o) => (
                            <TableRow key={o.start}>
                              <TableCell className='font-mono'>
                                {when(o.start)}
                              </TableCell>
                              <TableCell>
                                {formatDuration(o.duration)}
                                {o.ongoing ? ' (en curso)' : ''}
                              </TableCell>
                              <TableCell>
                                {(o.layer && LAYER_TEXT[o.layer]) ??
                                  o.layer ?? <Dash />}
                              </TableCell>
                              <TableCell>
                                {o.signal != null ? `${o.signal} %` : '—'}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </>
              )}
            </>
          )
        }}
      </QueryBoundary>
    </Box>
  )
}
