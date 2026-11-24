import { useMemo, useRef, useState } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { type Host } from '@/lib/api/schemas'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { useShortcuts } from '@/hooks/use-shortcuts'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataGrid } from './data-grid'
import { hostName, hostType, kindLabel, SOURCE_NOTE } from './labels'
import { NativeSelect } from './native-select'

const NUM = 'text-end tabular-nums'
const n = (v: number | null | undefined) => (v ?? 0).toLocaleString('es-AR')

const searchText = (h: Host) =>
  [
    h.ip,
    h.name,
    h.owner,
    h.note,
    h.mac,
    hostType(h),
    ...h.roles,
    ...h.protocols,
    ...h.alert_rules,
    ...h.services.map((s) => `${s.protocol}/${s.port}`),
  ]
    .filter(Boolean)
    .join(' ')

/** Tabla de equipos: una fila por IP. El texto de la captura se muestra siempre como texto. */
export function HostsTable({
  hosts,
  onOpen,
}: {
  hosts: Host[]
  onOpen: (ip: string) => void
}) {
  const [kind, setKind] = useState('')
  const [onlyAlerts, setOnlyAlerts] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  useShortcuts({ '/': () => searchRef.current?.focus() })

  const kinds = useMemo(() => [...new Set(hosts.map((h) => h.kind))], [hosts])
  const data = useMemo(
    () =>
      hosts.filter(
        (h) => (!kind || h.kind === kind) && (!onlyAlerts || h.alerts > 0)
      ),
    [hosts, kind, onlyAlerts]
  )

  const columns = useMemo<ColumnDef<Host, unknown>[]>(
    () => [
      {
        id: 'ip',
        accessorKey: 'ip',
        header: 'IP',
        cell: ({ row }) => (
          <Button
            variant='link'
            className='h-auto p-0 font-mono'
            onClick={() => onOpen(row.original.ip)}
            aria-label={`Ver el perfil de ${row.original.ip}`}
          >
            {row.original.ip}
          </Button>
        ),
      },
      {
        id: 'tipo',
        accessorFn: (h) => hostType(h),
        header: 'Tipo',
        cell: ({ row }) => (
          <div className='space-y-1'>
            <span>{hostType(row.original)}</span>
            {row.original.roles.length > 0 && (
              <ul className='flex flex-wrap gap-1' aria-label='Perfil del equipo'>
                {row.original.roles.map((r) => (
                  <li key={r}>
                    <Badge variant='secondary'>{r}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ),
      },
      {
        id: 'nombre',
        accessorFn: (h) => hostName(h).text,
        header: 'Nombre',
        cell: ({ row }) => {
          const nm = hostName(row.original)
          if (!nm.source) return <span className='text-muted-foreground'>—</span>
          return (
            <span
              className={cn('font-mono', nm.source !== 'captura' && 'text-muted-foreground')}
              title={SOURCE_NOTE[nm.source]}
            >
              {nm.text}
            </span>
          )
        },
      },
      {
        accessorKey: 'sessions',
        header: 'Sesiones',
        meta: { className: NUM },
        cell: ({ row }) => n(row.original.sessions),
      },
      {
        id: 'peers',
        accessorFn: (h) => h.peers ?? 0,
        header: 'Con quién habla',
        meta: { className: NUM },
        cell: ({ row }) => n(row.original.peers),
      },
      {
        accessorKey: 'bytes',
        header: 'Bytes',
        meta: { className: NUM },
        cell: ({ row }) => formatBytes(row.original.bytes),
      },
      {
        id: 'protocolos',
        accessorFn: (h) => h.protocols.join(', '),
        header: 'Protocolos',
        enableSorting: false,
      },
      {
        id: 'servicios',
        accessorFn: (h) => h.services.length,
        header: 'Servicios que ofrece',
        cell: ({ row }) =>
          row.original.services.length === 0 ? (
            <span className='text-muted-foreground'>—</span>
          ) : (
            <span className='font-mono text-xs'>
              {row.original.services.map((s) => `${s.protocol}/${s.port}`).join(' ')}
            </span>
          ),
      },
      {
        accessorKey: 'alerts',
        header: 'Alertas',
        meta: { className: NUM },
        cell: ({ row }) => {
          const h = row.original
          return (
            <span className='inline-flex flex-wrap items-center justify-end gap-1'>
              {h.alerts > 0 ? (
                <span>
                  {h.alerts} ({h.alert_rules.join(', ')})
                </span>
              ) : (
                <span className='text-muted-foreground'>0</span>
              )}
              {h.ioc.length > 0 && (
                <Badge
                  variant='outline'
                  className='border-sev-high/40 bg-sev-high/10 text-sev-high'
                  title={`Coincide con: ${h.ioc.map(String).join(', ')}`}
                >
                  IOC
                </Badge>
              )}
            </span>
          )
        },
      },
    ],
    [onOpen]
  )

  return (
    <DataGrid
      data={data}
      columns={columns}
      label='Equipos'
      searchText={searchText}
      searchRef={searchRef}
      searchPlaceholder='Buscar IP, nombre, MAC, servicio… (/)'
      emptyText='Ningún equipo coincide con el filtro.'
      rowClassName={(h) => (h.ioc.length > 0 ? 'bg-sev-high/5' : undefined)}
      toolbar={
        <>
          <NativeSelect
            label='Tipo'
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value=''>Todos</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {kindLabel(k)}
              </option>
            ))}
          </NativeSelect>
          <label className='flex items-center gap-2 text-sm'>
            <input
              type='checkbox'
              checked={onlyAlerts}
              onChange={(e) => setOnlyAlerts(e.target.checked)}
              className='size-4 accent-primary'
            />
            Solo con alertas
          </label>
        </>
      }
    />
  )
}
