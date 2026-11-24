import { useState } from 'react'
import { Download } from 'lucide-react'
import { useDownloadUrl } from '@/lib/api/mutations'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'

type Props = {
  url: string
  filename: string
  label: string
  /** Si se pasa, pide confirmación con este texto antes de descargar. */
  confirm?: string
}

/** Descarga con ticket de un solo uso (un <a download> no puede mandar el token). */
export function DownloadButton({ url, filename, label, confirm }: Props) {
  const ticket = useDownloadUrl()
  const [asking, setAsking] = useState(false)

  function start() {
    setAsking(false)
    ticket.mutate(url, {
      onSuccess: (href) => {
        const a = document.createElement('a')
        a.href = href
        a.download = filename
        document.body.appendChild(a)
        a.click()
        a.remove()
      },
    })
  }

  return (
    <>
      <Button
        type='button'
        variant='outline'
        size='sm'
        disabled={ticket.isPending}
        onClick={() => (confirm ? setAsking(true) : start())}
      >
        <Download /> {label}
      </Button>
      {confirm && (
        <ConfirmDialog
          open={asking}
          onOpenChange={setAsking}
          title='¿Descargar este archivo?'
          desc={confirm}
          cancelBtnText='Cancelar'
          confirmText='Descargar'
          destructive
          handleConfirm={start}
        />
      )}
    </>
  )
}
