import { useState } from 'react'
import { useWifi, useWifiHistory } from '@/lib/api/queries'
import { Badge } from '@/components/ui/badge'
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
import { Meter } from '@/features/soporte-sistema/components/meter'
import { RefreshButton } from '@/features/soporte-sistema/components/refresh-button'
import { Box, Dash, Fact, Facts, Notice } from './components/parts'
import { view, wifiExtra, wifiHistoryExtra } from './views'

const when = (iso: string) => {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('es-AR')
}

const speed = (v: number | null | undefined) => (v != null ? `${v} Mbps` : '—')

function History() {
  const [open, setOpen] = useState(false)
  const q = useWifiHistory({ enabled: open })
  return (
    <Box
      title='Historial de conexiones y desconexiones'
      actions={
        <Button
          variant='outline'
          size='sm'
          disabled={q.isFetching}
          onClick={() => (open ? void q.refetch() : setOpen(true))}
        >
          {q.isFetching
            ? 'Leyendo…'
            : open
              ? 'Volver a leer'
              : 'Ver el historial'}
        </Button>
      }
    >
      {open && (
        <QueryBoundary query={q}>
          {(h) => {
            const x = view(wifiHistoryExtra, h)
            if (!h.available)
              return (
                <Notice>
                  {x?.reason ?? 'El historial no está disponible.'}
                </Notice>
              )
            return (
              <>
                <p className='text-sm text-muted-foreground'>
                  {h.events.length} eventos recientes
                  {x?.disconnections != null &&
                    ` · ${x.disconnections} desconexiones`}
                </p>
                <div className='overflow-x-auto rounded-md border'>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Cuándo</TableHead>
                        <TableHead>Qué pasó</TableHead>
                        <TableHead>Detalle del sistema</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {h.events.map((e, i) => (
                        <TableRow key={`${e.time}-${i}`}>
                          <TableCell className='font-mono'>
                            {when(e.time)}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                e.kind === 'conectado' ? 'secondary' : 'outline'
                              }
                            >
                              {e.kind}
                            </Badge>
                          </TableCell>
                          <TableCell className='max-w-96 break-words text-muted-foreground'>
                            {e.message}
                          </TableCell>
                        </TableRow>
                      ))}
                      {h.events.length === 0 && (
                        <TableRow>
                          <TableCell
                            colSpan={3}
                            className='text-muted-foreground'
                          >
                            El sistema no registró eventos de Wi-Fi.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </div>
              </>
            )
          }}
        </QueryBoundary>
      )}
    </Box>
  )
}

/** «Wi-Fi»: señal, canal y velocidad de la conexión actual, más su historial. */
export function Wifi() {
  const q = useWifi({ refetchInterval: 5000 })
  return (
    <div className='space-y-4'>
      <Box
        title='Wi-Fi'
        topic='soporte_wifi'
        actions={
          <RefreshButton
            onClick={() => void q.refetch()}
            loading={q.isFetching}
            updatedAt={q.dataUpdatedAt}
          />
        }
      >
        <QueryBoundary query={q}>
          {(d) => {
            const x = view(wifiExtra, d)
            if (!d.available)
              return (
                <Notice>{x?.reason ?? 'No hay Wi-Fi en este equipo.'}</Notice>
              )
            if (!d.connected)
              return (
                <Notice>
                  {x?.reason ?? 'El Wi-Fi no está conectado a ninguna red.'}
                </Notice>
              )
            return (
              <>
                <Meter
                  goodHigh
                  label={`Señal${d.quality ? ` (${d.quality})` : ''}`}
                  percent={d.signal}
                  detail={
                    d.quality === 'débil'
                      ? 'La señal es débil: acercate al router o probá la banda de 2,4 GHz, que llega más lejos.'
                      : null
                  }
                />
                <Facts>
                  <Fact label='Red (SSID)' mono>
                    {d.ssid ?? <Dash />}
                  </Fact>
                  <Fact label='Canal / banda'>
                    {d.channel ?? '—'} / {d.band ?? '—'}
                  </Fact>
                  <Fact label='Tipo de Wi-Fi'>{d.radio ?? <Dash />}</Fact>
                  <Fact label='Seguridad'>{d.auth ?? <Dash />}</Fact>
                  <Fact label='Velocidad (recibe / envía)'>
                    {speed(d.rx)} / {speed(d.tx)}
                  </Fact>
                  <Fact label='Punto de acceso (BSSID)' mono>
                    {x?.bssid ?? <Dash />}
                  </Fact>
                </Facts>
              </>
            )
          }}
        </QueryBoundary>
      </Box>
      <History />
    </div>
  )
}
