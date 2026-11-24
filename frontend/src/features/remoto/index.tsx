import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import { type z } from 'zod'
import { type remoteAccessSchema } from '@/lib/api/schemas'
import { useRemoteAccess } from '@/lib/api/queries'
import { formatBytes, formatTime } from '@/lib/format'
import { RequireCapture } from '@/components/empty-capture'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { NativeSelect } from '@/features/equipos/components/native-select'

const SERVICES = ['SSH', 'Telnet', 'SMB', 'RDP', 'WinRM', 'VNC']
const n = (v: number) => v.toLocaleString('es-AR')
const NUM = 'text-end tabular-nums'

type Group = z.infer<typeof remoteAccessSchema>['services'][number]

function GroupTable({ group }: { group: Group }) {
  const id = `remote-${group.service}`
  return (
    <section className='space-y-2' aria-labelledby={id}>
      <h3 id={id} className='font-semibold'>
        {group.service}{' '}
        <span className='font-normal text-muted-foreground'>
          (puerto {group.ports.join(', ')})
        </span>
      </h3>
      <p className='text-sm text-muted-foreground'>
        {n(group.sessions)} sesiones · {n(group.clients)} cliente(s) · {n(group.servers)}{' '}
        servidor(es) · {n(group.with_rst)} con RST · {n(group.retries)} reintento(s) ·{' '}
        {formatBytes(group.bytes)}
      </p>
      <div className='overflow-x-auto rounded-md border'>
        <Table aria-label={`Sesiones ${group.service}`}>
          <TableHeader>
            <TableRow>
              <TableHead scope='col'>Cliente</TableHead>
              <TableHead scope='col'>Servidor</TableHead>
              <TableHead scope='col'>Dirección</TableHead>
              <TableHead scope='col'>Inicio</TableHead>
              <TableHead scope='col' className={NUM}>
                Paquetes
              </TableHead>
              <TableHead scope='col' className={NUM}>
                Bytes
              </TableHead>
              <TableHead scope='col' className={NUM}>
                RST
              </TableHead>
              <TableHead scope='col' className={NUM}>
                Reintentos
              </TableHead>
              <TableHead scope='col'>Señales</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {group.items.map((i) => (
              <TableRow
                key={i.id}
                className={i.rst_packets || i.syn_retries ? 'bg-sev-medium/10' : undefined}
              >
                <TableCell className='font-mono'>
                  <Link
                    to='/capturas/sesiones'
                    search={{ ip: i.client_ip, page: 1, size: 50 }}
                    className='underline-offset-4 hover:underline'
                    title='Ver las sesiones de este equipo'
                  >
                    {i.client_ip}
                  </Link>
                </TableCell>
                <TableCell className='font-mono'>
                  {i.server_ip}:{i.port}
                </TableCell>
                <TableCell>{i.direction ?? '—'}</TableCell>
                <TableCell>{formatTime(i.first_ts)}</TableCell>
                <TableCell className={NUM}>{n(i.packets)}</TableCell>
                <TableCell className={NUM}>{formatBytes(i.bytes)}</TableCell>
                <TableCell className={NUM}>{i.rst_packets ?? 0}</TableCell>
                <TableCell className={NUM}>{i.syn_retries ?? 0}</TableCell>
                <TableCell>
                  {i.signals.length ? (
                    i.signals.join(' · ')
                  ) : (
                    <span className='text-muted-foreground'>—</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {group.truncated && (
        <Alert role='note'>
          <AlertDescription>
            Se muestran las primeras {group.items.length} sesiones; el resumen cuenta
            todas.
          </AlertDescription>
        </Alert>
      )}
    </section>
  )
}

function RemotoContent() {
  const [service, setService] = useState('')
  const query = useRemoteAccess(service || undefined)
  return (
    <div className='space-y-4'>
      <NativeSelect
        label='Servicio'
        value={service}
        onChange={(e) => setService(e.target.value)}
      >
        <option value=''>Todos</option>
        {SERVICES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </NativeSelect>
      <p className='text-sm text-muted-foreground'>
        Conexiones a SSH (22), Telnet (23), SMB (445), RDP (3389), WinRM (5985/5986) y
        VNC (5900). Un RST o varios SYN seguidos pueden indicar un acceso rechazado o
        reintentos (por ejemplo, fuerza bruta), pero también un puerto cerrado o
        pérdida de paquetes.
      </p>
      <QueryBoundary
        query={query}
        isEmpty={(d) => d.total === 0}
        empty={
          <p className='text-sm text-muted-foreground'>
            No hay conexiones de acceso remoto{service ? ` por ${service}` : ''} en esta
            captura.
          </p>
        }
      >
        {(data) => (
          <div className='space-y-6'>
            {data.services.map((g) => (
              <GroupTable key={g.service} group={g} />
            ))}
          </div>
        )}
      </QueryBoundary>
    </div>
  )
}

export function Remoto() {
  return (
    <Page title='Acceso remoto' description='RDP, SSH, VNC y similares en la captura.'>
      <RequireCapture>
        <RemotoContent />
      </RequireCapture>
    </Page>
  )
}
