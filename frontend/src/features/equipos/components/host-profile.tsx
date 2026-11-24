import { useMemo } from 'react'
import { Link } from '@tanstack/react-router'
import { useGraph } from '@/lib/api/queries'
import { type Host } from '@/lib/api/schemas'
import { formatBytes } from '@/lib/format'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { CopyFilterButton } from './copy-filter'
import { hostName, hostType, SOURCE_NOTE } from './labels'

const n = (v: number | null | undefined) => (v ?? 0).toLocaleString('es-AR')

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className='text-xs text-muted-foreground'>{label}</dt>
      <dd className='font-medium tabular-nums'>{value}</dd>
    </div>
  )
}

/** Con quién habla un equipo, según las aristas del grafo (las de más tráfico primero). */
function Peers({ ip, onOpen }: { ip: string; onOpen: (ip: string) => void }) {
  const graph = useGraph()
  const peers = useMemo(() => {
    const edges = graph.data?.edges ?? []
    return edges
      .filter((e) => e.a === ip || e.b === ip)
      .map((e) => ({ ip: e.a === ip ? e.b : e.a, ...e }))
      .sort((x, y) => y.bytes - x.bytes)
  }, [graph.data, ip])
  if (peers.length === 0) return null
  return (
    <section aria-labelledby='peers-title' className='space-y-2'>
      <h3 id='peers-title' className='text-sm font-semibold'>
        Con quién habla
      </h3>
      <ul className='space-y-1 text-sm'>
        {peers.map((p) => (
          <li key={p.ip} className='flex flex-wrap items-center gap-x-2'>
            <Button
              variant='link'
              className='h-auto p-0 font-mono'
              onClick={() => onOpen(p.ip)}
            >
              {p.ip}
            </Button>
            <span className='text-muted-foreground'>
              {n(p.sessions)} sesión(es) · {formatBytes(p.bytes)}
              {p.protocols.length > 0 && ` · ${p.protocols.join(', ')}`}
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}

/** Perfil de un equipo en un panel lateral: datos, servicios, alertas y atajos a sesiones. */
export function HostProfile({
  host,
  onClose,
  onOpen,
}: {
  host: Host | null
  onClose: () => void
  onOpen: (ip: string) => void
}) {
  const nm = host ? hostName(host) : null
  return (
    <Sheet open={host !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className='w-full sm:max-w-lg'>
        {host && nm && (
          <>
            <SheetHeader>
              <SheetTitle className='font-mono'>{host.ip}</SheetTitle>
              <SheetDescription>
                {hostType(host)}
                {nm.source && (
                  <>
                    {' · '}
                    <span title={SOURCE_NOTE[nm.source]}>{nm.text}</span>
                  </>
                )}
              </SheetDescription>
            </SheetHeader>
            <ScrollArea className='min-h-0 flex-1 px-4'>
              <div className='space-y-4 pb-6'>
                {host.roles.length > 0 && (
                  <ul className='flex flex-wrap gap-1' aria-label='Perfil del equipo'>
                    {host.roles.map((r) => (
                      <li key={r}>
                        <Badge variant='secondary'>{r}</Badge>
                      </li>
                    ))}
                  </ul>
                )}
                <dl className='grid grid-cols-2 gap-3 text-sm sm:grid-cols-3'>
                  <Stat label='Sesiones' value={n(host.sessions)} />
                  <Stat label='Paquetes' value={n(host.packets)} />
                  <Stat label='Bytes' value={formatBytes(host.bytes)} />
                  <Stat label='Inició' value={n(host.initiated)} />
                  <Stat label='Recibió' value={n(host.received)} />
                  <Stat label='Con quién habla' value={n(host.peers)} />
                </dl>
                {host.mac && (
                  <p className='text-sm'>
                    <span className='text-muted-foreground'>MAC: </span>
                    <span className='font-mono'>{host.mac}</span>
                  </p>
                )}
                {host.protocols.length > 0 && (
                  <p className='text-sm'>
                    <span className='text-muted-foreground'>Protocolos: </span>
                    {host.protocols.join(', ')}
                  </p>
                )}
                <Separator />
                <section aria-labelledby='services-title' className='space-y-2'>
                  <h3 id='services-title' className='text-sm font-semibold'>
                    Servicios que ofrece
                  </h3>
                  {host.services.length === 0 ? (
                    <p className='text-sm text-muted-foreground'>
                      No ofreció servicios en esta captura.
                    </p>
                  ) : (
                    <ul className='flex flex-wrap gap-1'>
                      {host.services.map((s) => (
                        <li key={`${s.protocol}/${s.port}`}>
                          <Badge variant='outline' className='font-mono'>
                            {s.protocol}/{s.port} · {n(s.sessions)}
                          </Badge>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
                <section aria-labelledby='alerts-title' className='space-y-2'>
                  <h3 id='alerts-title' className='text-sm font-semibold'>
                    Alertas
                  </h3>
                  {host.alerts === 0 && host.ioc.length === 0 ? (
                    <p className='text-sm text-muted-foreground'>Sin alertas para este equipo.</p>
                  ) : (
                    <>
                      <p className='text-sm'>
                        {host.alerts} alerta(s)
                        {host.alert_rules.length > 0 && `: ${host.alert_rules.join(', ')}`}
                      </p>
                      {host.ioc.length > 0 && (
                        <p className='text-sm'>
                          <Badge
                            variant='outline'
                            className='me-2 border-sev-high/40 bg-sev-high/10 text-sev-high'
                          >
                            IOC
                          </Badge>
                          Coincide con: {host.ioc.map(String).join(', ')}
                        </p>
                      )}
                      <Button asChild variant='outline' size='sm'>
                        <Link to='/capturas/alertas'>Ver las alertas</Link>
                      </Button>
                    </>
                  )}
                </section>
                <Peers ip={host.ip} onOpen={onOpen} />
                <Separator />
                <div className='flex flex-wrap items-start gap-3'>
                  <Button asChild size='sm'>
                    <Link
                      to='/capturas/sesiones'
                      search={{ ip: host.ip, page: 1, size: 50 }}
                    >
                      Ver sus sesiones
                    </Link>
                  </Button>
                  <CopyFilterButton ip={host.ip} />
                </div>
              </div>
            </ScrollArea>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
