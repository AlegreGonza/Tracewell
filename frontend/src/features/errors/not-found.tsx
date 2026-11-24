import { Link } from '@tanstack/react-router'
import { Button } from '@/components/ui/button'

export function NotFound() {
  return (
    <div className='flex min-h-svh flex-col items-center justify-center gap-2 p-6 text-center'>
      <h1 className='text-6xl leading-tight font-bold'>404</h1>
      <p className='text-muted-foreground'>Esta pantalla no existe.</p>
      <Button asChild className='mt-4'>
        <Link to='/'>Volver al inicio</Link>
      </Button>
    </div>
  )
}
