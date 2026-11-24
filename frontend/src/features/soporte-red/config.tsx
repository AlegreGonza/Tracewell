import { useState } from 'react'
import { useNetConfig, useNetConfigRaw } from '@/lib/api/queries'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { QueryBoundary } from '@/components/query-boundary'
import { RefreshButton } from '@/features/soporte-sistema/components/refresh-button'
import { Box, Dash, Fact, Facts, Notice } from './components/parts'
import { configExtra, view } from './views'

const list = (a: string[]) => (a.length ? a.join(', ') : <Dash />)

function RawOutput() {
  const [open, setOpen] = useState(false)
  const raw = useNetConfigRaw({ enabled: open })
  return (
    <div className='space-y-2'>
      <Button variant='outline' size='sm' onClick={() => setOpen((v) => !v)}>
        {open
          ? 'Ocultar la salida del sistema'
          : 'Ver la salida completa del sistema'}
      </Button>
      {open && (
        <QueryBoundary query={raw}>
          {(r) =>
            r.available ? (
              <>
                <p className='text-sm text-muted-foreground'>
                  Comando: <code>{r.command}</code>
                </p>
                <pre className='max-h-96 overflow-auto rounded-md border p-3 text-xs whitespace-pre-wrap'>
                  {r.text}
                </pre>
              </>
            ) : (
              <Notice>No hay salida disponible en este sistema.</Notice>
            )
          }
        </QueryBoundary>
      )}
    </div>
  )
}

/** «Configuración»: cada adaptador con su IP, puerta de enlace y DNS. Solo lectura. */
export function Config() {
  const q = useNetConfig()
  return (
    <Box
      title='Configuración de red'
      topic='soporte_config'
      actions={
        <RefreshButton
          onClick={() => void q.refetch()}
          loading={q.isFetching}
          updatedAt={q.dataUpdatedAt}
        />
      }
    >
      <QueryBoundary query={q}>
        {(d) => (
          <>
            <p className='text-sm text-muted-foreground'>
              Equipo:{' '}
              <span className='font-mono'>
                {view(configExtra, d)?.hostname ?? '—'}
              </span>
            </p>
            <div className='grid gap-4 lg:grid-cols-2'>
              {d.adapters.map((a) => (
                <article
                  key={a.name}
                  className='space-y-3 rounded-md border p-4'
                >
                  <h3 className='flex items-center gap-2 font-medium'>
                    {a.name}
                    <Badge variant={a.up ? 'secondary' : 'outline'}>
                      {a.up ? 'conectado' : 'desconectado'}
                    </Badge>
                  </h3>
                  {a.apipa && (
                    <Notice warn>
                      Tiene una IP 169.254.x.x: la PC no consiguió una IP del
                      router (DHCP), así que no tiene Internet. Revisá el cable
                      o el Wi-Fi.
                    </Notice>
                  )}
                  <Facts>
                    <Fact label='Descripción'>{a.description ?? <Dash />}</Fact>
                    <Fact label='IP (IPv4)' mono>
                      {a.ipv4.length ? (
                        a.ipv4
                          .map((v) => `${v.ip} / ${v.mask ?? '?'}`)
                          .join(', ')
                      ) : (
                        <Dash />
                      )}
                    </Fact>
                    <Fact label='IP automática (DHCP)'>
                      {a.dhcp == null ? (
                        <Dash />
                      ) : a.dhcp ? (
                        'Sí'
                      ) : (
                        'No: IP fija'
                      )}
                    </Fact>
                    <Fact label='Puerta de enlace' mono>
                      {list(a.gateway)}
                    </Fact>
                    <Fact label='Servidores DNS' mono>
                      {list(a.dns)}
                    </Fact>
                    <Fact label='IPv6' mono>
                      {list(a.ipv6)}
                    </Fact>
                    <Fact label='Dirección física (MAC)' mono>
                      {a.mac ?? <Dash />}
                    </Fact>
                    <Fact label='Velocidad / MTU'>
                      {a.speed_mbps ? `${a.speed_mbps} Mbps` : '—'} /{' '}
                      {a.mtu ?? '—'}
                    </Fact>
                  </Facts>
                </article>
              ))}
            </div>
            <RawOutput />
          </>
        )}
      </QueryBoundary>
    </Box>
  )
}
