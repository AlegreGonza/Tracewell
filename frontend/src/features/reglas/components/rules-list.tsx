import { ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/severity-badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { mitreOf, type Rule } from '../api'

function Mitre({ rule }: { rule: Rule }) {
  const { tactic, technique, name } = mitreOf(rule)
  if (!tactic && !technique) {
    return <span className='text-muted-foreground'>—</span>
  }
  return (
    <div className='flex flex-col'>
      {tactic && <span>{tactic}</span>}
      {technique && (
        <span className='text-xs text-muted-foreground'>
          <span className='font-mono'>{technique}</span>
          {name ? ` · ${name}` : ''}
        </span>
      )}
    </div>
  )
}

/** Tabla de reglas activas: id, nombre, severidad y táctica/técnica MITRE. */
export function RulesList({ rules }: { rules: Rule[] }) {
  if (rules.length === 0) {
    return (
      <div className='flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center'>
        <ShieldCheck className='size-8 text-muted-foreground' aria-hidden />
        <p className='text-sm text-muted-foreground'>
          No hay reglas cargadas.
        </p>
      </div>
    )
  }
  return (
    <div className='overflow-x-auto rounded-md border'>
      <Table aria-label='Reglas de detección'>
        <TableHeader>
          <TableRow>
            <TableHead>Id</TableHead>
            <TableHead>Nombre</TableHead>
            <TableHead>Severidad</TableHead>
            <TableHead>MITRE ATT&amp;CK</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((r) => (
            <TableRow key={r.id}>
              <TableCell className='font-mono text-xs'>{r.id}</TableCell>
              <TableCell>
                <span>{r.name}</span>{' '}
                {r.custom && <Badge variant='secondary'>Propia</Badge>}
              </TableCell>
              <TableCell>
                <SeverityBadge severity={r.severity} />
              </TableCell>
              <TableCell>
                <Mitre rule={r} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
