import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'

/** Tabla en carga (en lugar de "Cargando…"). */
export function TableSkeleton({
  rows = 8,
  cols = 5,
  className,
}: {
  rows?: number
  cols?: number
  className?: string
}) {
  return (
    <div
      role='status'
      aria-label='Cargando datos'
      className={cn('space-y-2', className)}
    >
      <Skeleton className='h-9 w-full' />
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className='flex gap-3'>
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} className='h-6 flex-1' />
          ))}
        </div>
      ))}
    </div>
  )
}

/** Tarjeta en carga. */
export function CardSkeleton({ className }: { className?: string }) {
  return (
    <Card role='status' aria-label='Cargando datos' className={className}>
      <CardHeader>
        <Skeleton className='h-4 w-1/3' />
      </CardHeader>
      <CardContent className='space-y-2'>
        <Skeleton className='h-8 w-1/2' />
        <Skeleton className='h-3 w-full' />
        <Skeleton className='h-3 w-2/3' />
      </CardContent>
    </Card>
  )
}
