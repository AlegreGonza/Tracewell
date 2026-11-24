import { useMemo, useState } from 'react'
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type SortingState,
  useReactTable,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { type Alert } from '@/lib/api/schemas'
import { formatEndpoint, formatTime } from '@/lib/format'
import { SeverityBadge } from '@/components/severity-badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { severityRank } from '../attack'

type AlertRow = { key: string; alert: Alert }

const col = createColumnHelper<AlertRow>()

const columns = [
  col.accessor((r) => severityRank(r.alert.severity), {
    id: 'severity',
    header: 'Severidad',
    cell: (c) => <SeverityBadge severity={c.row.original.alert.severity} />,
    sortDescFirst: true,
  }),
  col.accessor((r) => r.alert.name, {
    id: 'name',
    header: 'Alerta',
    cell: (c) => c.getValue(),
  }),
  col.accessor((r) => r.alert.src_ip ?? '', {
    id: 'endpoints',
    header: 'Origen → destino',
    cell: (c) => (
      <span className='font-mono text-xs text-muted-foreground'>
        {formatEndpoint(c.row.original.alert.src_ip)} →{' '}
        {formatEndpoint(c.row.original.alert.dst_ip)}
      </span>
    ),
  }),
  col.accessor((r) => r.alert.mitre_technique ?? '', {
    id: 'technique',
    header: 'Técnica',
    cell: (c) => (
      <span className='font-mono text-xs'>{c.getValue() || '—'}</span>
    ),
  }),
  col.accessor((r) => r.alert.first_ts ?? 0, {
    id: 'time',
    header: 'Hora',
    cell: (c) => (
      <span className='font-mono text-xs whitespace-nowrap'>
        {formatTime(c.row.original.alert.first_ts)}
      </span>
    ),
  }),
]

type AlertsTableProps = {
  rows: AlertRow[]
  selectedKey?: string
  onOpen: (key: string) => void
}

/** Tabla de alertas ordenable; Enter o clic en el nombre abre el detalle. */
export function AlertsTable({ rows, selectedKey, onOpen }: AlertsTableProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'severity', desc: true },
  ])
  const data = useMemo(() => rows, [rows])
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getRowId: (r) => r.key,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <div className='overflow-x-auto rounded-md border'>
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((hg) => (
            <TableRow key={hg.id}>
              {hg.headers.map((h) => {
                const dir = h.column.getIsSorted()
                const Icon =
                  dir === 'asc' ? ArrowUp : dir === 'desc' ? ArrowDown : ArrowUpDown
                return (
                  <TableHead
                    key={h.id}
                    aria-sort={
                      dir === 'asc'
                        ? 'ascending'
                        : dir === 'desc'
                          ? 'descending'
                          : 'none'
                    }
                  >
                    <button
                      type='button'
                      onClick={h.column.getToggleSortingHandler()}
                      className='-ms-1 inline-flex items-center gap-1 rounded px-1 py-0.5 hover:bg-muted focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      <Icon className='size-3.5 opacity-70' aria-hidden='true' />
                    </button>
                  </TableHead>
                )
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.map((row) => (
            <TableRow
              key={row.id}
              data-state={row.id === selectedKey ? 'selected' : undefined}
              className='cursor-pointer'
              onClick={() => onOpen(row.id)}
            >
              {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id}>
                  {cell.column.id === 'name' ? (
                    <button
                      type='button'
                      onClick={(e) => {
                        e.stopPropagation()
                        onOpen(row.id)
                      }}
                      className='text-start font-medium underline-offset-2 hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </button>
                  ) : (
                    flexRender(cell.column.columnDef.cell, cell.getContext())
                  )}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
