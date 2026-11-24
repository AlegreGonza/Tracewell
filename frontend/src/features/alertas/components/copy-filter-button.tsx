import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'

/** Botón «Copiar filtro Wireshark»: copia y deja el filtro visible por si no hay portapapeles. */
export function CopyFilterButton({
  filter,
  label = 'Copiar filtro Wireshark',
}: {
  filter: string
  label?: string
}) {
  const [shown, setShown] = useState(false)
  const [copied, setCopied] = useState(false)

  async function copy() {
    setShown(true)
    try {
      await navigator.clipboard.writeText(filter)
      setCopied(true)
    } catch {
      setCopied(false) // sin permiso para el portapapeles: queda visible para copiarlo a mano
    }
  }

  return (
    <div className='space-y-1.5'>
      <Button type='button' variant='outline' size='sm' onClick={copy}>
        {copied ? <Check /> : <Copy />}
        {label}
      </Button>
      {shown && (
        <>
          <code className='block rounded-md bg-muted p-2 font-mono text-xs break-all'>
            {filter}
          </code>
          <p role='status' className='text-xs text-muted-foreground'>
            {copied ? 'Copiado' : 'No se pudo copiar solo: seleccionalo y copialo'}
          </p>
        </>
      )}
    </div>
  )
}
