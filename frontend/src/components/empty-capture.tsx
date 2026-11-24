import { type ReactNode } from 'react'
import { Link, useNavigate } from '@tanstack/react-router'
import { FileSearch } from 'lucide-react'
import { useDemo } from '@/lib/api/mutations'
import { useCapture } from '@/context/capture-provider'
import { Button } from '@/components/ui/button'
import { CardSkeleton } from '@/components/skeletons'

/** Estado vacío: invita a abrir una captura. */
function EmptyCapture() {
  const demo = useDemo()
  const navigate = useNavigate()
  return (
    <div
      data-testid='empty-capture'
      className='mx-auto flex max-w-md flex-col items-center gap-3 rounded-xl border border-dashed p-10 text-center'
    >
      <FileSearch className='size-10 text-muted-foreground' aria-hidden />
      <h2 className='text-lg font-semibold'>Sin captura cargada</h2>
      <p className='text-sm text-muted-foreground'>
        Abrí un archivo .pcap o .pcapng, capturá en vivo o probá con la captura
        de demostración para ver esta pantalla.
      </p>
      <div className='flex flex-wrap justify-center gap-2'>
        <Button asChild>
          <Link to='/'>Abrir una captura</Link>
        </Button>
        <Button
          variant='outline'
          disabled={demo.isPending}
          onClick={() =>
            demo.mutate(undefined, {
              onSuccess: () => void navigate({ to: '/capturas/alertas' }),
            })
          }
        >
          Probar con la demo
        </Button>
      </div>
    </div>
  )
}

/** Muestra `children` solo con una captura cargada; si no, el estado vacío. */
export function RequireCapture({ children }: { children: ReactNode }) {
  const { hasCapture, hydrating } = useCapture()
  if (hydrating) return <CardSkeleton />
  if (!hasCapture) return <EmptyCapture />
  return <>{children}</>
}
