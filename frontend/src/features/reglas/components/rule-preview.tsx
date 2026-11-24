import { AlertTriangle, Info } from 'lucide-react'
import { type z } from 'zod'
import { type rulePreviewSchema } from '@/lib/api/schemas'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'

type Preview = z.infer<typeof rulePreviewSchema>

const PLACEHOLDER = '# Completá el formulario para generar el YAML.'

function sampleLine(a: Record<string, unknown>): string {
  const ev = (a.evidence ?? {}) as Record<string, unknown>
  const events = ev.events != null ? `${ev.events} eventos` : 'coincide'
  const window =
    ev.window_seconds != null ? ` en ${ev.window_seconds} s` : ''
  return `${String(a.src_ip ?? '?')} → ${String(a.dst_ip ?? '?')}: ${events}${window}`
}

type Props = {
  preview: Preview | undefined
  loading: boolean
  error: string | null
  /** El formulario todavía no valida: no hay vista previa que mostrar. */
  incomplete: boolean
}

/** Coincidencias en vivo con la captura abierta y el YAML resultante. */
export function RulePreview({ preview, loading, error, incomplete }: Props) {
  const matches = preview?.matches
  return (
    <div className='space-y-4' aria-live='polite'>
      <section aria-labelledby='preview-title' className='space-y-2'>
        <h3 id='preview-title' className='text-sm font-semibold'>
          Vista previa con la captura abierta
        </h3>
        {error && (
          <Alert variant='destructive'>
            <AlertTriangle />
            <AlertTitle>La regla no es válida</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!error && loading && !preview && (
          <Skeleton
            className='h-12 w-full'
            role='status'
            aria-label='Calculando coincidencias'
          />
        )}
        {!error && incomplete && !preview && (
          <p className='text-sm text-muted-foreground'>
            Completá el nombre y corregí los campos marcados para ver las
            coincidencias.
          </p>
        )}
        {!error && preview && matches && (
          <div data-testid='rule-matches' className='space-y-2 text-sm'>
            <p>
              <strong>{matches.alerts.toLocaleString('es-AR')}</strong>{' '}
              alerta(s) y{' '}
              <strong>{matches.sessions.toLocaleString('es-AR')}</strong>{' '}
              sesión(es) coincidirían con esta captura. Todavía no se guardó
              nada.
            </p>
            {matches.sample.length > 0 && (
              <ul className='space-y-1 font-mono text-xs'>
                {matches.sample.map((a, i) => (
                  <li key={i}>{sampleLine(a)}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        {!error && preview && !matches && (
          <Alert>
            <Info />
            <AlertDescription>
              Abrí una captura para ver cuántas sesiones y alertas daría. El
              YAML igual se muestra abajo.
            </AlertDescription>
          </Alert>
        )}
        {preview?.exists && (
          <Alert variant='destructive'>
            <AlertTriangle />
            <AlertDescription>
              Ya existe una regla con el id <code>{preview.id}</code>: cambiá
              el nombre o el id para poder guardarla.
            </AlertDescription>
          </Alert>
        )}
      </section>
      <section aria-labelledby='yaml-title' className='space-y-2'>
        <h3 id='yaml-title' className='text-sm font-semibold'>
          YAML resultante
        </h3>
        <ScrollArea className='h-72 rounded-md border bg-muted/40'>
          <pre
            aria-labelledby='yaml-title'
            tabIndex={0}
            className='p-3 font-mono text-xs leading-relaxed'
          >
            {preview?.yaml ?? PLACEHOLDER}
          </pre>
        </ScrollArea>
      </section>
    </div>
  )
}
