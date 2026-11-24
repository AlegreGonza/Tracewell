import { useEffect } from 'react'
import { useDevicesScan, useDuplicateIpCheck } from '@/lib/api/mutations'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Box, Dash, Notice, RunButton, Verdict } from './components/parts'
import { devicesView, duplicateView, view } from './views'

/** Revisión de IP duplicada (ARP): la usa esta sección y las herramientas. */
function DuplicateIp() {
  const check = useDuplicateIpCheck()
  const r = check.data
  const x = r ? view(duplicateView, r) : null
  return (
    <div className='space-y-3'>
      <p className='text-sm text-muted-foreground'>
        Pregunta por ARP quién tiene la IP de esta PC y revisa los avisos de
        conflicto que el sistema ya anotó. La sonda necesita Npcap y abrir
        Tracewell como administrador.
      </p>
      <RunButton
        onClick={() => check.mutate()}
        busy={check.isPending}
        idle='Revisar IP duplicada'
        working='Revisando…'
      />
      {r && (
        <>
          <Verdict ok={!r.duplicate}>
            <p className='font-semibold'>{r.summary}</p>
            {r.advice && <p>{r.advice}</p>}
          </Verdict>
          <ul className='space-y-1 font-mono text-xs'>
            {x?.probes.map((p) => (
              <li key={`${p.adapter}-${p.ip}`}>
                {p.adapter} ({p.ip}):{' '}
                {p.probed
                  ? p.duplicate
                    ? `¡contestó otra MAC! ${p.other_macs.join(', ')}`
                    : 'sin otros equipos con esa IP'
                  : p.reason}
              </li>
            ))}
            {x?.conflicts.map((c, i) => (
              <li key={`${c.time}-${i}`}>
                Aviso del sistema ({c.time?.slice(0, 19).replace('T', ' ')}):{' '}
                {c.message}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

/** «Dispositivos»: quién está en la red local (tabla ARP o búsqueda con ping). */
export function Dispositivos() {
  const scan = useDevicesScan()
  const { mutate } = scan
  // Al entrar solo se lee la tabla ARP de la PC: no se manda nada a la red.
  useEffect(() => mutate(false), [mutate])
  const r = scan.data ? view(devicesView, scan.data) : null
  return (
    <div className='space-y-4'>
      <Box
        title='Dispositivos de la red'
        topic='soporte_dispositivos'
        actions={
          r && (
            <span className='text-sm text-muted-foreground'>
              {r.devices.length} dispositivos · red{' '}
              {r.subnets.join(', ') || '—'}
            </span>
          )
        }
      >
        <div className='flex flex-wrap items-center gap-3'>
          <RunButton
            onClick={() => mutate(true)}
            busy={scan.isPending}
            idle='Buscar en la red'
            working='Buscando…'
          />
          <RunButton
            onClick={() => mutate(false)}
            busy={scan.isPending}
            idle='Ver lo que ya conoce mi PC'
            working='Leyendo…'
          />
        </div>
        <p className='text-sm text-muted-foreground'>
          «Buscar» manda un ping a cada dirección de tu red (puede tardar 10–20
          segundos). No cambia nada.
        </p>
        {r && r.available === false && (
          <Notice>
            {r.reason ?? 'No se puede leer la red en este sistema.'}
          </Notice>
        )}
        {r && r.vendor_db === false && (
          <Notice>
            No hay base de fabricantes, así que no se muestra la marca de cada
            dispositivo. Para activarla, colocá la lista oficial de la IEEE
            (oui.csv) en la carpeta <code>data</code> de Tracewell.
          </Notice>
        )}
        {r && (
          <div className='overflow-x-auto rounded-md border'>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Nombre</TableHead>
                  <TableHead>Dirección física (MAC)</TableHead>
                  <TableHead>Marca</TableHead>
                  <TableHead>Notas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {r.devices.map((d) => (
                  <TableRow key={`${d.ip}-${d.mac}`}>
                    <TableCell className='font-mono'>{d.ip}</TableCell>
                    <TableCell className='font-mono break-words'>
                      {d.hostname ?? <Dash />}
                    </TableCell>
                    <TableCell className='font-mono'>
                      {d.mac ?? <Dash />}
                    </TableCell>
                    <TableCell className='break-words'>
                      {d.vendor ?? (
                        <span className='text-muted-foreground'>
                          {d.random_mac
                            ? 'MAC privada (aleatoria)'
                            : 'desconocida'}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className='space-x-1'>
                      {d.is_gateway && (
                        <Badge variant='secondary'>router</Badge>
                      )}
                      {d.is_self && <Badge variant='outline'>esta PC</Badge>}
                    </TableCell>
                  </TableRow>
                ))}
                {r.devices.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className='text-muted-foreground'>
                      Todavía no hay vecinos conocidos: probá «Buscar en la
                      red».
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </Box>
      <Box title='IP duplicada'>
        <DuplicateIp />
      </Box>
    </div>
  )
}
