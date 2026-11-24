import { cn } from '@/lib/utils'
import { type Session } from '@/lib/api/schemas'
import { Badge } from '@/components/ui/badge'

/** `ioc` solo viene en las sesiones que coinciden con un indicador de compromiso. */
export const iocOf = (s: Session): string[] =>
  Array.isArray(s.ioc) ? s.ioc.map(String) : []

const PROTO_COLOR: Record<string, string> = {
  TCP: 'border-chart-1/50 text-chart-1',
  UDP: 'border-chart-2/50 text-chart-2',
  ICMP: 'border-chart-3/50 text-chart-3',
  ICMPV6: 'border-chart-3/50 text-chart-3',
}

/** Etiqueta de protocolo con color por familia (el texto siempre dice cuál es). */
export function ProtocolBadge({ protocol }: { protocol: string }) {
  const cls = PROTO_COLOR[protocol.toUpperCase()] ?? 'text-muted-foreground'
  return (
    <Badge variant='outline' className={cn('font-mono', cls)}>
      {protocol}
    </Badge>
  )
}

// Un color por nombre de proceso (paleta de 5): el mismo programa se reconoce de un vistazo
const colors = new Map<string, number>()
function processColor(name: string) {
  if (!colors.has(name)) colors.set(name, (colors.size % 5) + 1)
  return colors.get(name)!
}

/** Nombre del proceso (puede ser cualquier cosa del sistema: solo texto). */
export function ProcessName({ process }: { process: Session['process'] }) {
  if (!process?.name) {
    return (
      <span
        className='text-muted-foreground'
        title='No se pudo identificar el proceso (por ejemplo, una conexión muy corta)'
      >
        —
      </span>
    )
  }
  return (
    <span
      className='inline-flex items-center gap-1.5 font-mono'
      title={`PID ${process.pid ?? '?'}`}
    >
      <span
        aria-hidden
        className='size-2 rounded-full'
        style={{ background: `var(--chart-${processColor(process.name)})` }}
      />
      {process.name}
    </span>
  )
}
