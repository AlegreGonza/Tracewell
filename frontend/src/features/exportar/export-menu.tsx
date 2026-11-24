import { useState } from 'react'
import { toast } from 'sonner'
import { Download, FileJson, FileText, Loader2, Network } from 'lucide-react'
import { api } from '@/lib/api/client'
import { useDownloadUrl } from '@/lib/api/mutations'
import { useCapture } from '@/context/capture-provider'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  SIEM_FORMATS,
  SIEM_SEVERITIES,
  siemUrl,
  triggerDownload,
  type SiemSeverity,
} from './downloads'

/** Menú «Exportar»: reportes, pcap filtrado y SIEM. Solo aparece con una captura cargada. */
export function ExportMenu() {
  const { hasCapture } = useCapture()
  const ticket = useDownloadUrl()
  const [minSeverity, setMinSeverity] = useState<SiemSeverity>('all')
  if (!hasCapture) return null

  // Pide un ticket de un solo uso y baja con esa URL; un fallo lo avisa el toast global.
  const download = (url: string, what: string) =>
    ticket.mutate(url, {
      onSuccess: (withTicket) => {
        triggerDownload(withTicket)
        toast.success(`Descargando ${what}`, { id: 'export-download' })
      },
    })

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant='outline' size='sm' disabled={ticket.isPending}>
          {ticket.isPending ? (
            <Loader2 className='animate-spin' aria-hidden />
          ) : (
            <Download aria-hidden />
          )}
          Exportar
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align='end' className='w-64'>
        <DropdownMenuLabel>Reportes</DropdownMenuLabel>
        <DropdownMenuGroup>
          <DropdownMenuItem
            onSelect={() => download(api.reportUrl(), 'el reporte HTML')}
          >
            <FileText aria-hidden /> Reporte HTML «Para el ticket»
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() => download(api.exportUrl(), 'el JSON')}
          >
            <FileJson aria-hidden /> Datos en JSON
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() => download(api.filteredPcapUrl(), 'el pcap')}
          >
            <Network aria-hidden /> Pcap filtrado
          </DropdownMenuItem>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Alertas para un SIEM</DropdownMenuLabel>
        <DropdownMenuGroup>
          {SIEM_FORMATS.map((f) => (
            <DropdownMenuItem
              key={f.value}
              onSelect={() =>
                download(siemUrl(f.value, minSeverity), `alertas ${f.label}`)
              }
            >
              <span className='flex flex-col'>
                <span>{f.label}</span>
                <span className='text-xs text-muted-foreground'>{f.hint}</span>
              </span>
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Severidad mínima del SIEM</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={minSeverity}
          onValueChange={(v) => setMinSeverity(v as SiemSeverity)}
        >
          {SIEM_SEVERITIES.map((s) => (
            <DropdownMenuRadioItem
              key={s.value}
              value={s.value}
              onSelect={(e) => e.preventDefault()}
            >
              {s.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
