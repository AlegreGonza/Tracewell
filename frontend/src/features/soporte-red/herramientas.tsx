import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { api } from '@/lib/api/client'
import {
  usePing,
  usePortScan,
  useRdpCheck,
  useTimeCheck,
  useTraceroute,
} from '@/lib/api/mutations'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Box, Notice, RunButton, SuggestedCommand } from './components/parts'
import { rdpView, timeView, traceView, view } from './views'

const PORT_STATE: Record<string, string> = {
  abierto: 'abierto',
  cerrado: 'cerrado',
  sin_respuesta: 'sin respuesta (¿filtrado?)',
  error: 'error',
}

function Tool({ title, children }: { title: string; children: ReactNode }) {
  return (
    <article className='space-y-3 rounded-md border p-4'>
      <h3 className='font-medium'>{title}</h3>
      {children}
    </article>
  )
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
}: {
  id: string
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  return (
    <div className='space-y-1.5'>
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  )
}

const submit = (fn: () => void) => (e: FormEvent) => {
  e.preventDefault()
  fn()
}

type PingLog = { t: number; ok: boolean; ms: number | null | undefined }

// Ping continuo: uno por segundo mientras la casilla esté marcada.
function useContinuousPing(host: string, on: boolean) {
  const [log, setLog] = useState<PingLog[]>([])
  useEffect(() => {
    if (!on || !host.trim()) return
    const ctl = new AbortController()
    const push = (e: PingLog) => setLog((l) => [e, ...l].slice(0, 60))
    const tick = async () => {
      const t = Date.now()
      try {
        const r = await api.supportPing(host, 1, ctl.signal)
        push({ t, ok: !!r.available && (r.received ?? 0) > 0, ms: r.avg })
      } catch {
        if (!ctl.signal.aborted) push({ t, ok: false, ms: null })
      }
    }
    void tick()
    const timer = setInterval(() => void tick(), 1000)
    return () => {
      ctl.abort()
      clearInterval(timer)
    }
  }, [host, on])
  return log
}

function PingTool() {
  const [host, setHost] = useState('')
  const [continuous, setContinuous] = useState(false)
  const once = usePing()
  const log = useContinuousPing(host, continuous)
  const r = once.data
  const lost = log.filter((h) => !h.ok).length
  return (
    <Tool title='Ping'>
      <form
        className='flex flex-wrap items-end gap-3'
        onSubmit={submit(() => once.mutate({ host, count: 4 }))}
      >
        <Field
          id='ping-host'
          label='Equipo o IP'
          value={host}
          onChange={setHost}
          placeholder='192.168.1.1 o www.example.com'
        />
        <RunButton
          type='submit'
          busy={once.isPending}
          disabled={!host.trim()}
          idle='Hacer ping (4)'
          working='Enviando…'
        />
        <div className='flex items-center gap-2 pb-2'>
          <Checkbox
            id='ping-cont'
            checked={continuous}
            disabled={!host.trim()}
            onCheckedChange={(v) => setContinuous(v === true)}
          />
          <Label htmlFor='ping-cont'>Ping continuo</Label>
        </div>
      </form>
      {r && r.available === false && <Notice>No se pudo hacer el ping.</Notice>}
      {r?.available && (
        <p className='text-sm'>
          {r.received} de {r.sent} respuestas ({r.loss_pct} % perdido) ·{' '}
          {r.avg != null
            ? `promedio ${r.avg} ms (mín ${r.min}, máx ${r.max})`
            : 'sin respuesta'}
        </p>
      )}
      {log.length > 0 && (
        <>
          <p className='text-sm text-muted-foreground'>
            {log.length} pings · {lost} sin respuesta
          </p>
          <ul className='max-h-40 overflow-auto font-mono text-xs'>
            {log.map((h) => (
              <li key={h.t} className={h.ok ? '' : 'text-destructive'}>
                {new Date(h.t).toLocaleTimeString('es-AR')} ·{' '}
                {h.ok ? `${h.ms} ms` : 'sin respuesta'}
              </li>
            ))}
          </ul>
        </>
      )}
    </Tool>
  )
}

function TraceTool() {
  const [host, setHost] = useState('')
  const trace = useTraceroute()
  const r = trace.data ? view(traceView, trace.data) : null
  return (
    <Tool title='Traza de ruta (tracert)'>
      <form
        className='flex flex-wrap items-end gap-3'
        onSubmit={submit(() => trace.mutate(host))}
      >
        <Field
          id='trace-host'
          label='Destino'
          value={host}
          onChange={setHost}
          placeholder='www.example.com'
        />
        <RunButton
          type='submit'
          busy={trace.isPending}
          disabled={!host.trim()}
          idle='Trazar'
          working='Trazando… (puede tardar 30 s)'
        />
      </form>
      {r && r.available === false && (
        <Notice>{r.reason ?? 'La traza no está disponible.'}</Notice>
      )}
      {r && r.available !== false && (
        <div className='overflow-x-auto rounded-md border'>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Salto</TableHead>
                <TableHead>Equipo</TableHead>
                <TableHead>Tiempos</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.hops.map((h) => (
                <TableRow key={h.n}>
                  <TableCell>{h.n}</TableCell>
                  <TableCell className='font-mono'>
                    {h.ips.length ? h.ips.join(', ') : 'sin respuesta'}
                  </TableCell>
                  <TableCell className='font-mono'>
                    {h.times.length
                      ? h.times.map((t) => `${t} ms`).join(' · ')
                      : '—'}
                  </TableCell>
                </TableRow>
              ))}
              {r.hops.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} className='text-muted-foreground'>
                    No se obtuvieron saltos.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </Tool>
  )
}

function PortsTool() {
  const [host, setHost] = useState('')
  const [ports, setPorts] = useState('22,80,443,3389')
  const scan = usePortScan()
  return (
    <Tool title='Puertos de un equipo'>
      <form
        className='flex flex-wrap items-end gap-3'
        onSubmit={submit(() => scan.mutate({ host, ports }))}
      >
        <Field
          id='ports-host'
          label='Equipo o IP'
          value={host}
          onChange={setHost}
          placeholder='192.168.1.20'
        />
        <Field
          id='ports-list'
          label='Puertos (hasta 20)'
          value={ports}
          onChange={setPorts}
        />
        <RunButton
          type='submit'
          busy={scan.isPending}
          disabled={!host.trim()}
          idle='Probar'
          working='Probando…'
        />
      </form>
      {scan.data && (
        <ul className='space-y-1 font-mono text-sm'>
          {scan.data.results.map((p) => (
            <li key={p.port}>
              {p.port}
              {p.service ? ` (${p.service})` : ''}:{' '}
              <strong>{PORT_STATE[p.state] ?? p.state}</strong>
              {p.ms != null ? ` · ${p.ms} ms` : ''}
            </li>
          ))}
        </ul>
      )}
    </Tool>
  )
}

function RdpTool() {
  const [host, setHost] = useState('')
  const rdp = useRdpCheck()
  const r = rdp.data ? view(rdpView, rdp.data) : null
  return (
    <Tool title='Acceso remoto (RDP)'>
      <form
        className='flex flex-wrap items-end gap-3'
        onSubmit={submit(() => rdp.mutate({ host, port: 3389 }))}
      >
        <Field
          id='rdp-host'
          label='Equipo o IP'
          value={host}
          onChange={setHost}
          placeholder='192.168.1.20'
        />
        <RunButton
          type='submit'
          busy={rdp.isPending}
          disabled={!host.trim()}
          idle='Probar RDP'
          working='Probando…'
        />
      </form>
      <p className='text-sm text-muted-foreground'>
        Manda una sola solicitud de conexión y se corta: no intenta iniciar
        sesión ni prueba contraseñas.
      </p>
      {r && <p className='font-semibold'>{r.summary}</p>}
    </Tool>
  )
}

const TIME_SERVERS = ['time.windows.com', 'pool.ntp.org', 'time.cloudflare.com']

function TimeTool() {
  const [server, setServer] = useState(TIME_SERVERS[0])
  const check = useTimeCheck()
  const r = check.data ? view(timeView, check.data) : null
  const off = r?.offset_seconds
  return (
    <Tool title='Hora de la PC'>
      <form
        className='flex flex-wrap items-end gap-3'
        onSubmit={submit(() => check.mutate(server))}
      >
        <div className='space-y-1.5'>
          <Label htmlFor='time-server'>Comparar con</Label>
          <select
            id='time-server'
            value={server}
            onChange={(e) => setServer(e.target.value)}
            className='h-9 rounded-md border bg-background px-2 text-sm'
          >
            {TIME_SERVERS.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </div>
        <RunButton
          type='submit'
          busy={check.isPending}
          idle='Comprobar hora'
          working='Consultando…'
        />
      </form>
      <p className='text-sm text-muted-foreground'>
        Le pregunta la hora a ese servidor público. Solo compara: no cambia el
        reloj.
      </p>
      {r && r.available === false && (
        <Notice>{r.reason ?? 'No se pudo comprobar la hora.'}</Notice>
      )}
      {r && r.available !== false && (
        <>
          <p className='text-sm'>
            <strong>{r.summary}</strong>
            {off != null && ` Diferencia: ${off > 0 ? '+' : ''}${off} s.`}
          </p>
          <SuggestedCommand command={r.command} />
        </>
      )}
    </Tool>
  )
}

/** «Herramientas»: pruebas sueltas sobre un equipo que elijas. Ninguna cambia nada. */
export function Herramientas() {
  return (
    <Box title='Herramientas' topic='soporte_herramientas'>
      <div className='grid gap-4 xl:grid-cols-2'>
        <PingTool />
        <TraceTool />
        <PortsTool />
        <RdpTool />
        <TimeTool />
      </div>
    </Box>
  )
}
