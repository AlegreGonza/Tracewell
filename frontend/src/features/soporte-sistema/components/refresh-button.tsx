import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'

type Props = {
  onClick: () => void
  loading: boolean
  /** Marca de tiempo (ms) de la última actualización. */
  updatedAt?: number
}

/** Botón «Actualizar» con comprobante de la última lectura (se anuncia a lectores de pantalla). */
export function RefreshButton({ onClick, loading, updatedAt }: Props) {
  return (
    <div className='flex items-center gap-2'>
      <span
        role='status'
        aria-live='polite'
        className='text-xs text-muted-foreground'
      >
        {loading
          ? 'Actualizando…'
          : updatedAt
            ? `Actualizado ${new Date(updatedAt).toLocaleTimeString('es-AR')}`
            : ''}
      </span>
      <Button
        type='button'
        variant='outline'
        size='sm'
        onClick={onClick}
        disabled={loading}
      >
        <RefreshCw className={loading ? 'animate-spin' : undefined} />
        Actualizar
      </Button>
    </div>
  )
}
