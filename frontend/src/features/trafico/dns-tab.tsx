import { useState } from 'react'
import { useDns } from '@/lib/api/queries'
import { formatTime } from '@/lib/format'
import { HelpTip } from '@/components/help-tip'
import { QueryBoundary } from '@/components/query-boundary'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

const n = (v: number) => v.toLocaleString('es-AR')
const NUM = 'text-end tabular-nums'
const DASH = <span className='text-muted-foreground'>—</span>

/** Pestaña DNS: nombres consultados, respuestas y pistas. Todo se muestra como texto. */
export function DnsTab() {
  const [text, setText] = useState('')
  const [applied, setApplied] = useState('')
  const query = useDns(applied || undefined)

  return (
    <section className='space-y-3' aria-labelledby='dns-title'>
      <div className='flex flex-wrap items-center gap-3'>
        <h2 id='dns-title' className='text-base font-semibold'>
          DNS
        </h2>
        <HelpTip topic='dns' />
        {query.data && (
          <span className='text-sm text-muted-foreground'>
            {n(query.data.summary.names)} nombres · {n(query.data.summary.queries)}{' '}
            consultas · {n(query.data.summary.nxdomain)} NXDOMAIN ·{' '}
            {n(query.data.summary.flagged)} con pistas
          </span>
        )}
      </div>
      <form
        className='flex gap-2'
        onSubmit={(e) => {
          e.preventDefault()
          setApplied(text.trim())
        }}
      >
        <Input
          type='search'
          aria-label='Buscar un nombre'
          placeholder='Buscar un nombre (por ejemplo: google)'
          value={text}
          onChange={(e) => setText(e.target.value)}
          className='h-8 w-full sm:w-80'
          autoComplete='off'
        />
        <Button type='submit' size='sm'>
          Buscar
        </Button>
      </form>
      <QueryBoundary
        query={query}
        isEmpty={(d) => d.items.length === 0}
        empty={
          <p className='text-sm text-muted-foreground'>
            {applied ? 'Ningún nombre coincide.' : 'La captura no tiene consultas DNS.'}
          </p>
        }
      >
        {(data) => (
          <div className='overflow-x-auto rounded-md border'>
            <Table aria-label='Consultas DNS'>
              <TableHeader>
                <TableRow>
                  <TableHead scope='col'>Nombre</TableHead>
                  <TableHead scope='col'>Tipo</TableHead>
                  <TableHead scope='col' className={NUM}>
                    Consultas
                  </TableHead>
                  <TableHead scope='col' className={NUM}>
                    Respuestas
                  </TableHead>
                  <TableHead scope='col'>Resultado</TableHead>
                  <TableHead scope='col'>Respondió</TableHead>
                  <TableHead scope='col' className={NUM}>
                    TTL mín.
                  </TableHead>
                  <TableHead scope='col'>Pistas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((r) => (
                  <TableRow
                    key={`${r.name}|${r.qtype}`}
                    title={`Visto de ${formatTime(r.first_ts)} a ${formatTime(r.last_ts)}`}
                  >
                    <TableCell className='font-mono break-all'>{r.name}</TableCell>
                    <TableCell className='font-mono'>{r.qtype}</TableCell>
                    <TableCell className={NUM}>{n(r.queries)}</TableCell>
                    <TableCell className={NUM}>{n(r.responses)}</TableCell>
                    <TableCell className='font-mono'>
                      {Object.entries(r.rcodes)
                        .map(([code, count]) => `${code}×${count}`)
                        .join(' ') || DASH}
                    </TableCell>
                    <TableCell className='font-mono break-all'>
                      {r.answers.join(', ') || DASH}
                    </TableCell>
                    <TableCell className={NUM}>{r.min_ttl ?? '—'}</TableCell>
                    <TableCell>
                      <div className='flex flex-col items-start gap-1'>
                        {r.hints.map((h) => (
                          <Badge key={h} variant='outline' className='whitespace-normal'>
                            {h}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </QueryBoundary>
    </section>
  )
}
