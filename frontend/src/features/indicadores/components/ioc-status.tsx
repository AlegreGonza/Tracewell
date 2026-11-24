import { ListChecks } from 'lucide-react'
import { type z } from 'zod'
import { type iocStatusSchema } from '@/lib/api/schemas'
import { Badge } from '@/components/ui/badge'

type Status = z.infer<typeof iocStatusSchema>

const fmt = (n: number) => n.toLocaleString('es-AR')

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className='rounded-lg border p-3'>
      <dt className='text-xs text-muted-foreground'>{label}</dt>
      <dd className='text-2xl font-semibold tabular-nums'>{fmt(value)}</dd>
    </div>
  )
}

/** Resumen de la lista cargada y de las sesiones que coinciden; o el estado vacío. */
export function IocStatus({ status }: { status: Status }) {
  if (!status.loaded) {
    return (
      <div className='flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center'>
        <ListChecks className='size-8 text-muted-foreground' aria-hidden />
        <p className='font-medium'>Sin lista cargada</p>
        <p className='max-w-md text-sm text-muted-foreground'>
          Cargá un archivo de indicadores para marcar los equipos, las alertas
          y las sesiones de la captura que coinciden con ellos.
        </p>
      </div>
    )
  }
  return (
    <div className='space-y-3' data-testid='ioc-status'>
      <p className='text-sm'>
        Lista cargada:{' '}
        <Badge variant='secondary' className='font-mono'>
          {status.source}
        </Badge>
      </p>
      <dl className='grid grid-cols-2 gap-3 md:grid-cols-4'>
        <Stat label='IP' value={status.ips} />
        <Stat label='Redes' value={status.networks} />
        <Stat label='Dominios' value={status.domains} />
        <Stat label='Sesiones que coinciden' value={status.sessions} />
      </dl>
      <p role='status' className='text-sm text-muted-foreground'>
        {status.sessions > 0
          ? `${fmt(status.sessions)} sesión(es) de la captura coinciden con la lista; las verás marcadas en Equipos, Alertas y Sesiones.`
          : 'Ninguna sesión de la captura coincide con la lista.'}
      </p>
    </div>
  )
}
