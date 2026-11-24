import { useMemo } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { type z } from 'zod'
import { useHostsByMac } from '@/lib/api/queries'
import { type macGroupSchema } from '@/lib/api/schemas'
import { formatBytes } from '@/lib/format'
import { QueryBoundary } from '@/components/query-boundary'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataGrid } from './data-grid'

type MacGroup = z.infer<typeof macGroupSchema>
const NUM = 'text-end tabular-nums'

const searchText = (g: MacGroup) =>
  [g.mac, ...g.ips, ...g.names, g.hint].filter(Boolean).join(' ')

/** «Equipos por MAC»: IP de la red local que comparten la misma dirección física. */
export function MacGroups({ onOpen }: { onOpen: (ip: string) => void }) {
  const query = useHostsByMac()
  const columns = useMemo<ColumnDef<MacGroup, unknown>[]>(
    () => [
      {
        accessorKey: 'mac',
        header: 'MAC',
        cell: ({ row }) => (
          <span className='font-mono'>
            {row.original.mac}
            {row.original.shared && (
              <Badge
                variant='outline'
                className='ms-2 border-sev-medium/40 bg-sev-medium/10 text-sev-medium'
              >
                varias IP
              </Badge>
            )}
          </span>
        ),
      },
      {
        id: 'ips',
        accessorFn: (g) => g.ips.length,
        header: 'IP',
        cell: ({ row }) => (
          <span className='flex flex-wrap gap-x-3'>
            {row.original.ips.map((ip) => (
              <Button
                key={ip}
                variant='link'
                className='h-auto p-0 font-mono'
                onClick={() => onOpen(ip)}
                aria-label={`Ver el perfil de ${ip}`}
              >
                {ip}
              </Button>
            ))}
          </span>
        ),
      },
      {
        accessorKey: 'sessions',
        header: 'Sesiones',
        meta: { className: NUM },
        cell: ({ row }) => row.original.sessions.toLocaleString('es-AR'),
      },
      {
        accessorKey: 'bytes',
        header: 'Bytes',
        meta: { className: NUM },
        cell: ({ row }) => formatBytes(row.original.bytes),
      },
      {
        id: 'pista',
        accessorFn: (g) => g.hint ?? '',
        header: 'Pista',
        enableSorting: false,
        cell: ({ row }) =>
          row.original.hint || <span className='text-muted-foreground'>—</span>,
      },
    ],
    [onOpen]
  )

  return (
    <QueryBoundary
      query={query}
      isEmpty={(d) => d.items.length === 0}
      empty={
        <p className='text-sm text-muted-foreground'>
          No hay direcciones MAC de la red local en esta captura.
        </p>
      }
    >
      {(data) => (
        <div className='space-y-3'>
          <p className='text-sm text-muted-foreground'>
            {data.total} MAC · {data.items.filter((g) => g.shared).length} con varias IP. Solo
            equipos de tu red local: la MAC de un destino en internet es la de tu router, así que
            no se muestra.
          </p>
          <DataGrid
            data={data.items}
            columns={columns}
            label='Equipos por MAC'
            searchText={searchText}
            searchPlaceholder='Buscar MAC o IP…'
            rowClassName={(g) => (g.shared ? 'bg-sev-medium/5' : undefined)}
          />
        </div>
      )}
    </QueryBoundary>
  )
}
