import { Link } from '@tanstack/react-router'
import { ExternalLink } from 'lucide-react'
import { type Alert } from '@/lib/api/schemas'
import { useSessions } from '@/lib/api/queries'
import { formatEndpoint, formatTime } from '@/lib/format'
import { SeverityBadge } from '@/components/severity-badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { techniqueUrl } from '../attack'
import { CopyFilterButton } from './copy-filter-button'
import { DownloadPcapButton } from './download-pcap-button'

const MAX_SESSIONS = 8

function List({ title, items, ordered }: { title: string; items: string[]; ordered?: boolean }) {
  if (items.length === 0) return null
  const Tag = ordered ? 'ol' : 'ul'
  return (
    <section className='space-y-1'>
      <h3 className='text-sm font-semibold'>{title}</h3>
      <Tag
        className={`ms-5 space-y-1 text-sm text-muted-foreground ${ordered ? 'list-decimal' : 'list-disc'}`}
      >
        {items.map((t, i) => (
          <li key={i}>{t}</li>
        ))}
      </Tag>
    </section>
  )
}

/** Sesiones de la IP de origen que también tocan el destino de la alerta. */
function RelatedSessions({ alert }: { alert: Alert }) {
  const src = alert.src_ip
  const query = useSessions({ ip: src ?? undefined, limit: 200 }, { enabled: !!src })
  if (!src) return null
  return (
    <section className='space-y-1.5' aria-labelledby='related-title'>
      <h3 id='related-title' className='text-sm font-semibold'>
        Sesiones relacionadas
      </h3>
      {query.isError ? (
        <p className='text-sm text-muted-foreground'>
          No se pudieron cargar las sesiones.
        </p>
      ) : !query.data ? (
        <Skeleton className='h-16 w-full' role='status' aria-label='Cargando sesiones' />
      ) : (
        (() => {
          const all = query.data.items.filter(
            (s) => !alert.dst_ip || s.src_ip === alert.dst_ip || s.dst_ip === alert.dst_ip
          )
          const items = all.slice(0, MAX_SESSIONS)
          if (items.length === 0) {
            return (
              <p className='text-sm text-muted-foreground'>
                No hay sesiones entre estas direcciones.
              </p>
            )
          }
          return (
            <>
              <ul className='divide-y rounded-md border text-sm'>
                {items.map((s) => (
                  <li key={s.id}>
                    <Link
                      to='/capturas/sesiones'
                      search={{ sesion: s.id, ip: src, page: 1, size: 50 }}
                      className='flex flex-wrap items-center gap-x-2 px-2 py-1.5 hover:bg-muted focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
                    >
                      <span className='font-mono text-xs text-muted-foreground'>
                        #{s.id}
                      </span>
                      <span>{s.protocol}</span>
                      <span className='font-mono text-xs'>
                        {formatEndpoint(s.src_ip, s.src_port)} →{' '}
                        {formatEndpoint(s.dst_ip, s.dst_port)}
                      </span>
                      <span className='ms-auto text-xs text-muted-foreground'>
                        {s.packets} paq.
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
              {all.length > items.length && (
                <p className='text-xs text-muted-foreground'>
                  Se muestran {items.length} de {all.length}.{' '}
                  <Link
                    to='/capturas/sesiones'
                    search={{ ip: src, page: 1, size: 50 }}
                    className='underline'
                  >
                    Ver todas las sesiones de {src}
                  </Link>
                </p>
              )}
            </>
          )
        })()
      )}
    </section>
  )
}

type AlertDetailProps = {
  alert: Alert | null
  onClose: () => void
}

/** Panel lateral con el detalle de una alerta: qué pasó, evidencia, guía y sesiones. */
export function AlertDetail({ alert, onClose }: AlertDetailProps) {
  return (
    <Sheet open={!!alert} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className='w-full gap-0 overflow-y-auto sm:max-w-xl'>
        {alert && (
          <>
            <SheetHeader>
              <div className='flex flex-wrap items-center gap-2'>
                <SeverityBadge severity={alert.severity} />
                <span className='font-mono text-xs text-muted-foreground'>
                  {alert.rule_id}
                </span>
              </div>
              <SheetTitle>{alert.name}</SheetTitle>
              <SheetDescription>
                {formatEndpoint(alert.src_ip)} → {formatEndpoint(alert.dst_ip)} ·{' '}
                {formatTime(alert.first_ts)}
              </SheetDescription>
            </SheetHeader>
            <div className='space-y-4 px-4 pb-6'>
              <p className='text-sm'>{alert.description}</p>
              {alert.mitre_technique && (
                <p className='text-sm'>
                  <strong>MITRE ATT&amp;CK:</strong>{' '}
                  <a
                    href={techniqueUrl(alert.mitre_technique)}
                    target='_blank'
                    rel='noopener noreferrer'
                    className='inline-flex items-center gap-0.5 font-mono underline'
                  >
                    {alert.mitre_technique}
                    <ExternalLink className='size-3' aria-hidden='true' />
                    <span className='sr-only'>(pestaña nueva)</span>
                  </a>{' '}
                  — {alert.mitre_name}
                  {alert.mitre_tactic ? ` (${alert.mitre_tactic})` : ''}
                </p>
              )}
              {alert.guide && (
                <div className='space-y-3 rounded-lg border bg-muted/30 p-3'>
                  <List title='Posibles falsos positivos' items={alert.guide.false_positives} />
                  <List title='Cómo investigarla' items={alert.guide.investigation_steps} ordered />
                  {alert.guide.wireshark_filter && (
                    <p className='text-sm'>
                      Filtro de Wireshark de la regla:{' '}
                      <code className='font-mono text-xs break-all'>
                        {alert.guide.wireshark_filter}
                      </code>
                    </p>
                  )}
                </div>
              )}
              <section className='space-y-1'>
                <h3 className='text-sm font-semibold'>Evidencia</h3>
                {/* Texto plano: la evidencia viene de tráfico que puede ser hostil, nunca se interpreta como HTML. */}
                <pre className='max-h-64 overflow-auto rounded-md bg-muted p-2 font-mono text-xs'>
                  {JSON.stringify(alert.evidence, null, 2)}
                </pre>
              </section>
              <div className='flex flex-wrap gap-2'>
                {alert.wireshark_filter && (
                  <CopyFilterButton filter={alert.wireshark_filter} />
                )}
                {alert.src_ip && <DownloadPcapButton ip={alert.src_ip} />}
              </div>
              <RelatedSessions alert={alert} />
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
