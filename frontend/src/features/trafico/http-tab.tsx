import { Link } from '@tanstack/react-router'
import { type z } from 'zod'
import { type httpOverviewItemSchema } from '@/lib/api/schemas'
import { useHttpOverview } from '@/lib/api/queries'
import { formatBytes } from '@/lib/format'
import { HelpTip } from '@/components/help-tip'
import { QueryBoundary } from '@/components/query-boundary'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

type Item = z.infer<typeof httpOverviewItemSchema>

const NUM = 'text-end tabular-nums'

/** Notas en lenguaje simple de un intercambio: lo que merece una mirada. */
function httpNotes(ex: Item): string[] {
  const notes: string[] = []
  if (ex.sensitive_fields.length)
    notes.push(`Envía un campo de contraseña SIN cifrar: ${ex.sensitive_fields.join(', ')}`)
  if (ex.auth) notes.push(`Autenticación ${ex.auth} sin cifrar`)
  if (ex.location) notes.push(`Redirige a ${ex.location}`)
  if (ex.complete === false) notes.push('Incompleto: faltan bytes en la captura')
  return notes
}

const hasCredentials = (ex: Item) => ex.sensitive_fields.length > 0 || Boolean(ex.auth)

function ipOf(ex: Item) {
  if (ex.src_ip) return ex.src_ip
  const src = ex.src ?? ''
  return src.slice(0, src.lastIndexOf(':'))
}

function FileNote({ file }: { file: NonNullable<Item['file']> }) {
  const hash = (file.sha256 ?? '').slice(0, 16)
  return (
    <Badge variant={file.risky ? 'destructive' : 'outline'} className='whitespace-normal'>
      Archivo {file.name}: {file.kind} · SHA-256 {hash}…
    </Badge>
  )
}

function Row({ ex }: { ex: Item }) {
  const ip = ipOf(ex)
  return (
    <TableRow>
      <TableCell className='font-mono'>
        #{ex.session_id}{' '}
        {ip ? (
          <Link
            to='/capturas/sesiones'
            search={{ ip, page: 1, size: 50 }}
            className='underline-offset-4 hover:underline'
            title='Ver las sesiones de este origen'
          >
            {ex.src}
          </Link>
        ) : (
          ex.src
        )}
      </TableCell>
      <TableCell className='font-mono break-all'>
        <strong>{ex.method}</strong> {ex.host ?? ex.dst}
        {ex.target}
      </TableCell>
      <TableCell className={`${NUM} font-mono`}>{ex.status ?? '—'}</TableCell>
      <TableCell className='font-mono'>{ex.response_type ?? '—'}</TableCell>
      <TableCell className={NUM}>{formatBytes(ex.response_bytes)}</TableCell>
      <TableCell>
        <div className='flex flex-col items-start gap-1'>
          {httpNotes(ex).map((note) => (
            <Badge key={note} variant='outline' className='break-all whitespace-normal'>
              {note}
            </Badge>
          ))}
          {ex.file && <FileNote file={ex.file} />}
        </div>
      </TableCell>
    </TableRow>
  )
}

/** Pestaña HTTP sin cifrar de toda la captura. */
export function HttpTab() {
  const query = useHttpOverview()
  const items = query.data?.items ?? []
  return (
    <section className='space-y-3' aria-labelledby='http-title'>
      <div className='flex flex-wrap items-center gap-3'>
        <h2 id='http-title' className='text-base font-semibold'>
          HTTP sin cifrar
        </h2>
        <HelpTip topic='http' />
        {query.data && (
          <span className='text-sm text-muted-foreground'>
            {items.length} petición(es) · {items.filter((e) => e.file).length}{' '}
            archivo(s) · {items.filter(hasCredentials).length} con credenciales
          </span>
        )}
      </div>
      <QueryBoundary
        query={query}
        isEmpty={(d) => d.items.length === 0}
        empty={
          <p className='text-sm text-muted-foreground'>
            No hay tráfico HTTP sin cifrar en esta captura.
          </p>
        }
      >
        {(data) => (
          <>
            {data.capped && (
              <Alert role='note'>
                <AlertDescription>
                  Se muestran solo las primeras: la captura tiene más HTTP del que se
                  lee de una vez.
                </AlertDescription>
              </Alert>
            )}
            <div className='overflow-x-auto rounded-md border'>
              <Table aria-label='Peticiones HTTP'>
                <TableHeader>
                  <TableRow>
                    <TableHead scope='col'>Sesión</TableHead>
                    <TableHead scope='col'>Pedido</TableHead>
                    <TableHead scope='col' className={NUM}>
                      Estado
                    </TableHead>
                    <TableHead scope='col'>Tipo</TableHead>
                    <TableHead scope='col' className={NUM}>
                      Tamaño
                    </TableHead>
                    <TableHead scope='col'>Notas</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((ex) => (
                    <Row key={`${ex.session_id}-${ex.index}`} ex={ex} />
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}
      </QueryBoundary>
    </section>
  )
}
