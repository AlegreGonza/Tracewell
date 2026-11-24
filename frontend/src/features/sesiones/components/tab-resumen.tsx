import { useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api/client'
import {
  formatBytes,
  formatDuration,
  formatEndpoint,
  formatTime,
} from '@/lib/format'
import { useSaveNote } from '@/lib/api/mutations'
import { useExplain } from '@/lib/api/queries'
import { type Session } from '@/lib/api/schemas'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { QueryBoundary } from '@/components/query-boundary'
import { CardSkeleton } from '@/components/skeletons'
import { CopyFilterButton } from './copy-filter-button'
import { DownloadButton } from './download-button'
import { ProcessName, iocOf } from './session-meta'

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div>
      <dt className='text-xs text-muted-foreground'>{label}</dt>
      <dd className='text-sm break-all'>{children}</dd>
    </div>
  )
}

type Step = {
  who: string
  label: string
  detail?: string | null
  ts?: number | null
}

/** Diagrama paso a paso de la conexión (como el «Flow Graph» de Wireshark). */
function Ladder({
  steps,
  origin,
  destination,
}: {
  steps: Step[]
  origin: string
  destination: string
}) {
  return (
    <div className='rounded-md border'>
      <div className='flex justify-between gap-2 border-b bg-muted/40 px-3 py-1.5 font-mono text-xs'>
        <span>Origen · {origin}</span>
        <span className='text-end'>Destino · {destination}</span>
      </div>
      <ol className='divide-y'>
        {steps.map((s, i) => {
          const toDest = s.who === 'origen'
          const toOrigin = s.who === 'destino'
          const spoken = toDest
            ? 'Origen → Destino'
            : toOrigin
              ? 'Destino → Origen'
              : ''
          return (
            <li
              key={i}
              aria-label={`${spoken ? spoken + ': ' : ''}${s.label}. ${s.detail ?? ''}`}
              className='grid grid-cols-[5.5rem_3rem_1fr] items-baseline gap-2 px-3 py-1.5 text-xs'
            >
              <span className='font-mono font-medium'>{s.label}</span>
              <span aria-hidden className='font-mono text-primary'>
                {toDest ? '───▶' : toOrigin ? '◀───' : '· · ·'}
              </span>
              <span className='text-muted-foreground'>
                {s.detail}
                {s.ts != null && (
                  <span className='font-mono'> · {formatTime(s.ts)}</span>
                )}
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

function Explanation({ session }: { session: Session }) {
  const query = useExplain(session.id)
  return (
    <section aria-labelledby='explain-title' className='space-y-3'>
      <h3 id='explain-title' className='font-semibold'>
        En palabras simples
      </h3>
      <QueryBoundary query={query} skeleton={<CardSkeleton />}>
        {(data) => (
          <>
            <ul className='list-disc space-y-1 ps-5 text-sm'>
              {data.summary.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
            {data.steps.length > 0 && (
              <Ladder
                steps={data.steps}
                origin={session.src_ip}
                destination={session.dst_ip}
              />
            )}
            <CopyFilterButton filter={data.wireshark_filter} />
          </>
        )}
      </QueryBoundary>
    </section>
  )
}

function NoteForm({ session }: { session: Session }) {
  const save = useSaveNote()
  const [note, setNote] = useState(session.note ?? '')
  const [reviewed, setReviewed] = useState(Boolean(session.reviewed))

  function submit(e: React.FormEvent) {
    e.preventDefault()
    save.mutate(
      { id: session.id, note, reviewed },
      { onSuccess: () => toast.success('Nota guardada') }
    )
  }

  return (
    <form
      onSubmit={submit}
      className='space-y-2'
      aria-label='Nota del analista'
    >
      <Label htmlFor='session-note'>Nota del analista</Label>
      <Textarea
        id='session-note'
        value={note}
        onChange={(e) => setNote(e.target.value)}
        maxLength={2000}
        rows={3}
        placeholder='Ej.: es el keep-alive de una app conocida, legítimo'
      />
      <div className='flex items-center gap-2'>
        <Checkbox
          id='session-reviewed'
          checked={reviewed}
          onCheckedChange={(v) => setReviewed(v === true)}
        />
        <Label htmlFor='session-reviewed'>Marcar como revisada</Label>
      </div>
      <Button type='submit' size='sm' disabled={save.isPending}>
        Guardar nota
      </Button>
    </form>
  )
}

export function TabResumen({ session }: { session: Session }) {
  const ioc = iocOf(session)
  return (
    <div className='space-y-5'>
      <dl className='grid grid-cols-2 gap-3'>
        <Field label='Origen'>
          <span className='font-mono'>
            {formatEndpoint(session.src_ip, session.src_port)}
          </span>
        </Field>
        <Field label='Destino'>
          <span className='font-mono'>
            {formatEndpoint(session.dst_ip, session.dst_port)}
          </span>
        </Field>
        <Field label='Paquetes'>
          {session.packets.toLocaleString('es-AR')}
        </Field>
        <Field label='Bytes'>{formatBytes(session.bytes)}</Field>
        <Field label='Duración'>{formatDuration(session.duration)}</Field>
        <Field label='Inicio'>{formatTime(session.first_ts)}</Field>
        {session.direction && (
          <Field label='Dirección'>{session.direction}</Field>
        )}
        {session.host && (
          <Field label='Sitio'>
            <span className='font-mono'>{session.host}</span>
          </Field>
        )}
        {/* La clave `process` solo existe en una captura en vivo */}
        {'process' in session && (
          <Field label='Proceso'>
            {session.process ? (
              <>
                <ProcessName process={session.process} />{' '}
                <span className='text-muted-foreground'>
                  (PID {session.process.pid ?? '?'})
                </span>
              </>
            ) : (
              <span className='text-muted-foreground'>no identificado</span>
            )}
          </Field>
        )}
      </dl>

      {ioc.length > 0 && (
        <Alert>
          <AlertDescription>
            Coincide con un indicador de compromiso:{' '}
            <span className='font-mono'>{ioc.join(', ')}</span>
          </AlertDescription>
        </Alert>
      )}

      <div className='flex flex-wrap items-start gap-2'>
        <DownloadButton
          url={api.sessionPcapUrl(session.id)}
          filename={`tracewell-sesion-${session.id}.pcap`}
          label='Descargar .pcap de esta sesión'
        />
      </div>

      <NoteForm key={session.id} session={session} />
      <Explanation session={session} />
    </div>
  )
}
