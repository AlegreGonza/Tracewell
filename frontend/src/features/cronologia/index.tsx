import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import { useCaseTimeline } from '@/lib/api/queries'
import { formatTime, severityLabel } from '@/lib/format'
import { RequireCapture } from '@/components/empty-capture'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

// Etiqueta en texto (nunca solo color) de cada tipo de hecho.
const KIND_LABEL: Record<string, string> = {
  alerta: 'Alerta',
  dns: 'DNS',
  ioc: 'IOC',
  sesion: 'Sesión',
}

function CronologiaContent() {
  const [text, setText] = useState('')
  const [host, setHost] = useState('')
  const query = useCaseTimeline(host || undefined)

  return (
    <div className='space-y-4'>
      <p className='text-sm text-muted-foreground'>
        Alertas, consultas DNS sospechosas, sesiones que marcaste y
        coincidencias con IOC, en el orden en que ocurrieron. Horas en UTC.
      </p>
      <form
        className='flex flex-wrap gap-2'
        onSubmit={(e) => {
          e.preventDefault()
          setHost(text.trim())
        }}
      >
        <Input
          type='search'
          aria-label='Equipo (IP)'
          className='max-w-xs'
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder='Limitar a un equipo (IP)'
          autoComplete='off'
        />
        <Button type='submit' variant='secondary'>
          Limitar al equipo
        </Button>
        {host && (
          <Button
            type='button'
            variant='ghost'
            onClick={() => {
              setText('')
              setHost('')
            }}
          >
            Quitar filtro
          </Button>
        )}
      </form>
      <QueryBoundary
        query={query}
        isEmpty={(d) => d.items.length === 0}
        empty={
          <p className='text-sm text-muted-foreground'>
            No hay hechos para mostrar{host ? ' de ese equipo' : ''}.
          </p>
        }
      >
        {(data) => (
          <>
            <p className='text-sm text-muted-foreground'>
              {data.total.toLocaleString('es-AR')} hechos
              {data.host ? ` de ${data.host}` : ''}
            </p>
            <ol
              aria-label='Hechos del caso en orden cronológico'
              className='divide-y rounded-md border'
            >
              {data.items.map((e, i) => (
                <li
                  key={`${e.kind}-${e.ts}-${i}`}
                  className='flex flex-wrap items-start gap-x-3 gap-y-1 px-3 py-2 text-sm'
                >
                  <time className='font-mono text-xs text-muted-foreground'>
                    {formatTime(e.ts)}
                  </time>
                  <Badge variant='outline'>{KIND_LABEL[e.kind] ?? e.kind}</Badge>
                  <span className='min-w-0 flex-1'>
                    <strong>{e.title}</strong>
                    {e.severity && (
                      <span className='text-muted-foreground'>
                        {' '}
                        · {severityLabel(e.severity)}
                      </span>
                    )}
                    {e.detail && (
                      <span className='block break-words text-muted-foreground'>
                        {e.detail}
                      </span>
                    )}
                  </span>
                  {e.ips[0] && (
                    <Link
                      to='/capturas/sesiones'
                      search={{ ip: e.ips[0], page: 1, size: 50 }}
                      className='text-xs underline underline-offset-4'
                    >
                      Ver sesiones de {e.ips[0]}
                    </Link>
                  )}
                </li>
              ))}
            </ol>
            {data.truncated && (
              <Alert role='note'>
                <AlertDescription>
                  Hay más hechos: se muestran los primeros {data.items.length}.
                  Filtrá por un equipo para ver el resto.
                </AlertDescription>
              </Alert>
            )}
          </>
        )}
      </QueryBoundary>
    </div>
  )
}

export function Cronologia() {
  return (
    <Page title='Cronología del caso' description='Qué pasó y en qué orden.'>
      <RequireCapture>
        <CronologiaContent />
      </RequireCapture>
    </Page>
  )
}
