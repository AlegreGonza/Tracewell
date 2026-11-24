import { Download } from 'lucide-react'
import { api } from '@/lib/api/client'
import { useDownloadUrl } from '@/lib/api/mutations'
import { Button } from '@/components/ui/button'

/** Descarga los paquetes de una IP como .pcap (pide un ticket de un solo uso). */
export function DownloadPcapButton({ ip }: { ip: string }) {
  const ticket = useDownloadUrl()
  return (
    <Button
      type='button'
      variant='outline'
      size='sm'
      disabled={ticket.isPending}
      onClick={() =>
        ticket.mutate(api.filteredPcapUrl({ ip }), {
          onSuccess: (href) => {
            const a = document.createElement('a')
            a.href = href
            a.download = ''
            a.click()
          },
        })
      }
    >
      <Download />
      Descargar .pcap de {ip}
    </Button>
  )
}
