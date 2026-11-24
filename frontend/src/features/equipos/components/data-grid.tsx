import { useMemo, useState, type ReactNode } from 'react'
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

type DataGridProps<T> = {
  data: T[]
  columns: ColumnDef<T, unknown>[]
  /** Nombre accesible de la tabla. */
  label: string
  /** Texto en el que busca el filtro (todo en minúsculas se compara sin acentos de caja). */
  searchText: (row: T) => string
  searchPlaceholder?: string
  /** Se muestra cuando el filtro no deja ninguna fila. */
  emptyText?: string
  pageSize?: number
  rowClassName?: (row: T) => string | undefined
  /** Contenido extra en la barra de herramientas (por ejemplo, un selector). */
  toolbar?: ReactNode
  /** Ref del campo de búsqueda (para el atajo "/"). */
  searchRef?: React.Ref<HTMLInputElement>
}

const SORT_ICON = {
  asc: <ArrowUp className='size-3.5' aria-hidden />,
  desc: <ArrowDown className='size-3.5' aria-hidden />,
  none: <ChevronsUpDown className='size-3.5 opacity-60' aria-hidden />,
}

/** Tabla con búsqueda, orden por columna (aria-sort) y paginación sobre TanStack Table. */
export function DataGrid<T>({
  data,
  columns,
  label,
  searchText,
  searchPlaceholder = 'Filtrar…',
  emptyText = 'Nada coincide con el filtro.',
  pageSize = 25,
  rowClassName,
  toolbar,
  searchRef,
}: DataGridProps<T>) {
  const [sorting, setSorting] = useState<SortingState>([])
  const [globalFilter, setGlobalFilter] = useState('')
  const globalFilterFn = useMemo(
    () => (row: { original: T }, _id: string, value: string) =>
      searchText(row.original).toLowerCase().includes(String(value).toLowerCase()),
    [searchText]
  )
  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  })
  const rows = table.getRowModel().rows
  const filtered = table.getFilteredRowModel().rows.length
  const pages = table.getPageCount()
  const page = table.getState().pagination.pageIndex + 1

  return (
    <div className='space-y-3'>
      <div className='flex flex-wrap items-center gap-2'>
        <Input
          ref={searchRef}
          type='search'
          aria-label={`Filtrar ${label.toLowerCase()}`}
          placeholder={searchPlaceholder}
          value={globalFilter}
          onChange={(e) => setGlobalFilter(e.target.value)}
          className='h-8 w-full sm:w-72'
          autoComplete='off'
        />
        {toolbar}
        <span className='ms-auto text-xs text-muted-foreground' role='status'>
          {filtered.toLocaleString('es-AR')} de {data.length.toLocaleString('es-AR')}
        </span>
      </div>
      <div className='overflow-x-auto rounded-md border'>
        <Table aria-label={label}>
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted()
                  const text = header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.header, header.getContext())
                                    return (
                    <TableHead
                      key={header.id}
                      scope='col'
                      aria-sort={
                        sorted === 'asc'
                          ? 'ascending'
                          : sorted === 'desc'
                            ? 'descending'
                            : header.column.getCanSort()
                              ? 'none'
                              : undefined
                      }
                      className={cn(header.column.columnDef.meta?.className)}
                    >
                      {header.column.getCanSort() ? (
                        <Button
                          variant='ghost'
                          size='sm'
                          className='-mx-2 h-8'
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {text}
                          {SORT_ICON[sorted || 'none']}
                        </Button>
                      ) : (
                        text
                      )}
                    </TableHead>
                  )
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className='h-20 text-center text-muted-foreground'
                >
                  {emptyText}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow key={row.id} className={rowClassName?.(row.original)}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell
                      key={cell.id}
                      className={cn(cell.column.columnDef.meta?.className)}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {pages > 1 && (
        <nav
          aria-label={`Páginas de ${label.toLowerCase()}`}
          className='flex items-center justify-end gap-2 text-sm'
        >
          <Button
            variant='outline'
            size='sm'
            disabled={!table.getCanPreviousPage()}
            onClick={() => table.previousPage()}
          >
            Anterior
          </Button>
          <span aria-live='polite'>
            Página {page} de {pages}
          </span>
          <Button
            variant='outline'
            size='sm'
            disabled={!table.getCanNextPage()}
            onClick={() => table.nextPage()}
          >
            Siguiente
          </Button>
        </nav>
      )}
    </div>
  )
}
