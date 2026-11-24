import { Link } from '@tanstack/react-router'
import { errorMessage } from '@/lib/api/errors'
import { Button } from '@/components/ui/button'

/** Error inesperado al dibujar una pantalla (incluye una respuesta que no calza con el esquema). */
export function GeneralError({ error }: { error?: unknown }) {
  return (
    <div
      role='alert'
      className='flex min-h-svh flex-col items-center justify-center gap-2 p-6 text-center'
    >
      <h1 className='text-4xl leading-tight font-bold'>Algo salió mal</h1>
      <p className='max-w-xl text-muted-foreground'>
        {error ? errorMessage(error) : 'Ocurrió un error inesperado.'}
      </p>
      <div className='mt-4 flex gap-2'>
        <Button variant='outline' onClick={() => window.location.reload()}>
          Recargar
        </Button>
        <Button asChild>
          <Link to='/'>Volver al inicio</Link>
        </Button>
      </div>
    </div>
  )
}
