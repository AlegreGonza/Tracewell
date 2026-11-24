import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { toast } from 'sonner'
import { useWiresharkFilter } from '@/lib/api/queries'
import { Button } from '@/components/ui/button'

/** Botón «Copiar filtro Wireshark» de un equipo; deja el filtro a la vista por si no hay portapapeles. */
export function CopyFilterButton({ ip }: { ip: string }) {
  const query = useWiresharkFilter(ip)
  const [copied, setCopied] = useState(false)
  const filter = query.data?.wireshark_filter

  async function copy() {
    if (!filter) return
    try {
      await navigator.clipboard.writeText(filter)
      setCopied(true)
      toast.success('Filtro copiado')
    } catch {
      setCopied(false)
      toast.message('No se pudo copiar solo: seleccioná el filtro y copialo a mano.')
    }
  }

  return (
    <div className='space-y-2'>
      <Button
        type='button'
        variant='outline'
        size='sm'
        disabled={!filter}
        onClick={() => void copy()}
      >
        {copied ? <Check /> : <Copy />} Copiar filtro Wireshark
      </Button>
      {filter && (
        <code className='block rounded bg-muted px-2 py-1 font-mono text-xs break-all select-all'>
          {filter}
        </code>
      )}
    </div>
  )
}
