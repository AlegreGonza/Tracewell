import { useNavigate } from '@tanstack/react-router'
import { FileSearch, X } from 'lucide-react'
import { toast } from 'sonner'
import { useCloseCapture } from '@/lib/api/mutations'
import { useCapture } from '@/context/capture-provider'
import useDialogState from '@/hooks/use-dialog-state'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'

const fmt = new Intl.NumberFormat('es-AR')

/** Pie de la barra lateral: qué captura hay cargada y cómo cerrarla. */
export function CaptureStatus() {
  const { capture, hydrating } = useCapture()
  const close = useCloseCapture()
  const navigate = useNavigate()
  const [open, setOpen] = useDialogState<'close'>()

  if (!capture) {
    return (
      <div className='rounded-lg border border-dashed p-3 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden'>
        <FileSearch className='mb-1 size-4' />
        {hydrating ? 'Buscando captura…' : 'Sin captura cargada'}
      </div>
    )
  }

  const { stats } = capture
  return (
    <div className='rounded-lg border bg-card p-3 text-xs group-data-[collapsible=icon]:hidden'>
      <div className='flex items-start justify-between gap-2'>
        <p className='min-w-0 truncate font-medium' title={capture.source}>
          {capture.source}
        </p>
        <Button
          variant='ghost'
          size='icon'
          className='-me-1 -mt-1 size-6 shrink-0'
          aria-label='Cerrar captura'
          onClick={() => setOpen('close')}
        >
          <X />
        </Button>
      </div>
      <p className='mt-1 text-muted-foreground'>
        {fmt.format(stats.packets)} paquetes · {fmt.format(stats.sessions)}{' '}
        sesiones · {fmt.format(capture.alerts)} alertas
      </p>
      <ConfirmDialog
        open={open === 'close'}
        onOpenChange={(o) => setOpen(o ? 'close' : null)}
        title='¿Cerrar la captura?'
        desc='Se descarta el análisis actual (el archivo no se borra). Las notas y marcas de revisado de la sesión también se pierden.'
        confirmText='Cerrar captura'
        cancelBtnText='Cancelar'
        isLoading={close.isPending}
        handleConfirm={() =>
          close.mutate(undefined, {
            onSuccess: () => {
              setOpen(null)
              toast.success('Captura cerrada')
              void navigate({ to: '/' })
            },
          })
        }
      />
    </div>
  )
}
