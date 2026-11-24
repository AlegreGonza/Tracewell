import { type ReactNode } from 'react'
import { type UseQueryResult } from '@tanstack/react-query'
import { SYSTEM_NOTE, SYSTEM_SECTIONS } from '@/config/support-sections'
import { formatBytes, formatDuration } from '@/lib/format'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  type Hint,
  useActiveConnections,
  useOpenPorts,
  useOverview,
  useProcessList,
  useServiceList,
  useStartupList,
} from './api'
import { Meter } from './components/meter'
import { Notice } from './components/notice'
import { RefreshButton } from './components/refresh-button'
import { Dash, Fact, Facts, SectionCard } from './components/section-card'
import { hintLabel } from './hints'

const POLL = { refetchInterval: 5000 }

function Hints({ hints }: { hints?: Hint[] }) {
  if (!hints?.length) return null
  return (
    <span className='ms-2 inline-flex flex-wrap gap-1'>
      {hints.map((h) => (
        <Badge key={h.code} variant='outline' title={h.text ?? undefined}>
          {hintLabel(h.code)}
        </Badge>
      ))}
    </span>
  )
}

/** Tabla simple de solo lectura: cabeceras y filas ya armadas. */
function Grid({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <div className='overflow-x-auto rounded-md border'>
      <Table>
        <TableHeader>
          <TableRow>
            {head.map((h) => (
              <TableHead key={h}>{h}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((cells, i) => (
            <TableRow key={i}>
              {cells.map((c, j) => (
                <TableCell key={j} className='max-w-80 break-words'>
                  {c ?? <Dash />}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

/** Tarjeta con su consulta: título, ayuda, botón «Actualizar» y el contenido. */
function Section<T>({
  id,
  title,
  query,
  children,
}: {
  id: string
  title: string
  query: UseQueryResult<T>
  children: (data: T) => ReactNode
}) {
  return (
    <SectionCard
      title={title}
      topic={`sistema_${id}`}
      actions={
        <RefreshButton
          onClick={() => void query.refetch()}
          loading={query.isFetching}
          updatedAt={query.dataUpdatedAt}
        />
      }
    >
      <QueryBoundary query={query}>{children}</QueryBoundary>
    </SectionCard>
  )
}

const NotSupported = ({ reason }: { reason?: string | null }) => (
  <Notice>{reason ?? 'Esta sección no está disponible en este sistema.'}</Notice>
)

function Resumen() {
  const q = useOverview(POLL)
  return (
    <Section id='resumen' title='Resumen del equipo' query={q}>
      {(d) => (
        <>
          <div className='grid gap-4 sm:grid-cols-2'>
            <Meter label='Procesador' percent={d.cpu_percent} />
            <Meter
              label='Memoria'
              percent={d.memory?.percent}
              detail={
                d.memory &&
                `${formatBytes(d.memory.used)} de ${formatBytes(d.memory.total)}`
              }
            />
            {d.disks.map((disk) => (
              <Meter
                key={disk.mount}
                label={`Disco ${disk.mount}`}
                percent={disk.percent}
                detail={`${formatBytes(disk.used)} de ${formatBytes(disk.total)}`}
              />
            ))}
          </div>
          <Facts>
            <Fact label='Encendido hace'>{formatDuration(d.uptime_seconds)}</Fact>
            <Fact label='Procesos'>{d.process_count ?? <Dash />}</Fact>
            <Fact label='Núcleos'>{d.cpu_count ?? <Dash />}</Fact>
            <Fact label='Red enviada'>
              {d.network_total ? formatBytes(d.network_total.sent) : <Dash />}
            </Fact>
            <Fact label='Red recibida'>
              {d.network_total ? formatBytes(d.network_total.received) : <Dash />}
            </Fact>
          </Facts>
        </>
      )}
    </Section>
  )
}

function Procesos() {
  const q = useProcessList('ram', POLL)
  return (
    <Section id='procesos' title='Procesos' query={q}>
      {(d) => (
        <>
          <p className='text-sm text-muted-foreground'>
            {d.total} procesos; se muestran los que más memoria usan.
          </p>
          <Grid
            head={['PID', 'Nombre', 'Usuario', 'CPU %', 'Memoria', 'Conexiones']}
            rows={d.items.map((p) => [
              p.pid,
              <>
                {p.name}
                <Hints hints={p.hints} />
              </>,
              p.user,
              p.cpu?.toFixed(1),
              p.rss != null ? formatBytes(p.rss) : null,
              p.connections,
            ])}
          />
        </>
      )}
    </Section>
  )
}

function Puertos() {
  const q = useOpenPorts()
  return (
    <Section id='puertos' title='Puertos abiertos' query={q}>
      {(d) => (
        <Grid
          head={['Protocolo', 'Dirección', 'Puerto', 'Servicio', 'Programa', 'Exposición']}
          rows={d.items.map((p) => [
            p.proto,
            p.ip,
            p.port,
            p.service,
            p.process,
            p.exposure_text ?? p.exposure,
          ])}
        />
      )}
    </Section>
  )
}

function Conexiones() {
  const q = useActiveConnections(POLL)
  return (
    <Section id='conexiones' title='Conexiones activas' query={q}>
      {(d) => (
        <Grid
          head={['Programa', 'Local', 'Remoto', 'Estado', 'Servicio']}
          rows={d.items.map((c) => [c.process, c.local, c.remote, c.status, c.service])}
        />
      )}
    </Section>
  )
}

function Servicios() {
  const q = useServiceList()
  return (
    <Section id='servicios' title='Servicios' query={q}>
      {(d) =>
        !d.supported ? (
          <NotSupported reason={d.reason} />
        ) : (
          <Grid
            head={['Servicio', 'Estado', 'Inicio', 'Ejecutable']}
            rows={d.items.map((s) => [
              <>
                {s.display ?? s.name}
                <Hints hints={s.hints} />
              </>,
              s.status,
              s.start,
              s.path,
            ])}
          />
        )
      }
    </Section>
  )
}

function Inicio() {
  const q = useStartupList()
  return (
    <Section id='inicio' title='Programas de inicio' query={q}>
      {(d) =>
        !d.supported ? (
          <NotSupported reason={d.reason} />
        ) : (
          <Grid
            head={['Dónde', 'Nombre', 'Comando']}
            rows={d.items.map((s) => [
              s.where,
              <>
                {s.name}
                <Hints hints={s.hints} />
              </>,
              s.command,
            ])}
          />
        )
      }
    </Section>
  )
}

const SECCIONES: Record<string, () => ReactNode> = {
  resumen: Resumen,
  procesos: Procesos,
  puertos: Puertos,
  conexiones: Conexiones,
  servicios: Servicios,
  inicio: Inicio,
}

/** Soporte del sistema, solo lectura: `seccion` ya viene validada contra SYSTEM_SECTIONS. */
export function SoporteSistema({ seccion }: { seccion: string }) {
  const label = SYSTEM_SECTIONS.find((s) => s.id === seccion)?.label ?? seccion
  const Contenido = SECCIONES[seccion]
  return (
    <Page title={`Sistema · ${label}`} description={SYSTEM_NOTE}>
      <Contenido />
    </Page>
  )
}
