import { type ReactNode } from 'react'
import { type UseQueryResult } from '@tanstack/react-query'
import { AlertCircle, RotateCw } from 'lucide-react'
import { errorMessage } from '@/lib/api/errors'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { TableSkeleton } from '@/components/skeletons'

type QueryBoundaryProps<T> = {
  query: UseQueryResult<T>
  /** Qué se muestra mientras carga (por defecto, una tabla en esqueleto). */
  skeleton?: ReactNode
  /** Si devuelve true, se muestra `empty` en vez de los datos. */
  isEmpty?: (data: T) => boolean
  empty?: ReactNode
  children: (data: T) => ReactNode
}

/**
 * Esqueleto mientras carga, error claro con "Reintentar" (nunca pantalla en blanco)
 * y los datos ya validados por el esquema zod cuando llegan.
 */
export function QueryBoundary<T>({
  query,
  skeleton,
  isEmpty,
  empty,
  children,
}: QueryBoundaryProps<T>) {
  if (query.isError) {
    return (
      <Alert variant='destructive'>
        <AlertCircle />
        <AlertTitle>No se pudo cargar</AlertTitle>
        <AlertDescription>
          <p>{errorMessage(query.error)}</p>
          <Button
            variant='outline'
            size='sm'
            className='mt-2'
            onClick={() => void query.refetch()}
          >
            <RotateCw /> Reintentar
          </Button>
        </AlertDescription>
      </Alert>
    )
  }
  if (query.data === undefined) return <>{skeleton ?? <TableSkeleton />}</>
  if (isEmpty?.(query.data)) return <>{empty ?? null}</>
  return <>{children(query.data)}</>
}
