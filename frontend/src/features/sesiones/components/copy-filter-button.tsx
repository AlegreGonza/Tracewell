import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'

type Props = {
  /** Filtro de Wireshark; si falta, el botón avisa que no hay uno. */
  filter: string | null | undefined
  label?: string
}

/** Botón «Copiar filtro Wireshark»: copia al portapapeles y deja el texto a la vista. */
export function CopyFilterButton({
  filter,
  label = 'Copiar filtro Wireshark',
}: Props) {
  const [shown, setShown] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function copy() {
    setCopied(false)
    if (!filter) {
      toast.error('No hay un filtro de Wireshark para esto.')
      return
    }
    setShown(filter)
    try {
      await navigator.clipboard.writeText(filter)
      setCopied(true)
    } catch {
      /* sin permiso para el portapapeles: queda visible para copiarlo a mano */
    }
  }

  return (
    <div className='flex flex-col gap-1'>
      <Button type='button' variant='outline' size='sm' onClick={copy}>
        {copied ? <Check /> : <Copy />} {label}
      </Button>
      {shown && (
        <>
          <code className='rounded bg-muted px-2 py-1 font-mono text-xs break-all'>
            {shown}
          </code>
          <span role='status' className='text-xs text-muted-foreground'>
            {copied
              ? 'Copiado'
              : 'No se pudo copiar solo: seleccionalo y copialo'}
          </span>
        </>
      )}
    </div>
  )
}
