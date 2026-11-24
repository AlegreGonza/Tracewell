import { getRouteApi } from '@tanstack/react-router'
import { useSessions } from '@/lib/api/queries'
import { formatBytes, formatEndpoint, formatTime } from '@/lib/format'
import { RequireCapture } from '@/components/empty-capture'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useSessionById } from './api'
import { ProtocolBadge } from './components/session-meta'
import { TabResumen } from './components/tab-resumen'

const route = getRouteApi('/_app/capturas/sesiones/')

function Detail({ id, onClose }: { id?: number; onClose: () => void }) {
  const { data: session } = useSessionById(id)
  return (
    <Sheet open={id !== undefined} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className='w-full overflow-y-auto sm:max-w-xl'>
        <SheetHeader>
          <SheetTitle>Sesión #{id}</SheetTitle>
          <SheetDescription>
            {session
              ? `${session.protocol} · ${formatEndpoint(session.src_ip, session.src_port)} → ${formatEndpoint(session.dst_ip, session.dst_port)}`
              : 'Cargando…'}
          </SheetDescription>
        </SheetHeader>
        <div className='px-4 pb-6'>
          {session && <TabResumen session={session} />}
        </div>
      </SheetContent>
    </Sheet>
  )
}

function SesionesContent() {
  const { protocol, ip, port, page, size, sesion } = route.useSearch()
  const navigate = route.useNavigate()
  const query = useSessions({
    protocol,
    ip,
    port,
    limit: size,
    offset: (page - 1) * size,
  })
  const set = (patch: Record<string, unknown>) =>
    void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true })
  const onEnter =
    (key: 'ip' | 'protocol') => (e: React.KeyboardEvent<HTMLInputElement>) =>
      e.key === 'Enter' &&
      set({ [key]: e.currentTarget.value.trim() || undefined, page: 1 })

  return (
    <div className='space-y-3'>
      <div className='flex flex-wrap gap-2'>
        <Input
          aria-label='Filtrar por IP'
          placeholder='IP (Enter para filtrar)'
          className='w-56'
          defaultValue={ip ?? ''}
          onKeyDown={onEnter('ip')}
        />
        <Input
          aria-label='Filtrar por protocolo'
          placeholder='Protocolo'
          className='w-36'
          defaultValue={protocol ?? ''}
          onKeyDown={onEnter('protocol')}
        />
      </div>
      <QueryBoundary
        query={query}
        isEmpty={(d) => d.items.length === 0}
        empty={
          <p className='text-sm text-muted-foreground'>
            No hay sesiones con estos filtros.
          </p>
        }
      >
        {(data) => (
          <>
            <div className='overflow-x-auto rounded-md border'>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>#</TableHead>
                    <TableHead>Protocolo</TableHead>
                    <TableHead>Origen → destino</TableHead>
                    <TableHead>Paquetes</TableHead>
                    <TableHead>Bytes</TableHead>
                    <TableHead>Inicio</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((s) => (
                    <TableRow
                      key={s.id}
                      className='cursor-pointer'
                      data-state={s.id === sesion ? 'selected' : undefined}
                      onClick={() => set({ sesion: s.id })}
                    >
                      <TableCell className='font-mono text-xs'>
                        {s.id}
                      </TableCell>
                      <TableCell>
                        <ProtocolBadge protocol={s.protocol} />
                      </TableCell>
                      <TableCell className='font-mono text-xs'>
                        {formatEndpoint(s.src_ip, s.src_port)} →{' '}
                        {formatEndpoint(s.dst_ip, s.dst_port)}
                      </TableCell>
                      <TableCell>{s.packets}</TableCell>
                      <TableCell>{formatBytes(s.bytes)}</TableCell>
                      <TableCell className='font-mono text-xs whitespace-nowrap'>
                        {formatTime(s.first_ts)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className='flex items-center justify-between text-sm'>
              <span className='text-muted-foreground'>
                {data.total.toLocaleString('es-AR')} sesiones · página {page}
              </span>
              <div className='flex gap-2'>
                <Button
                  variant='outline'
                  size='sm'
                  disabled={page <= 1}
                  onClick={() => set({ page: page - 1 })}
                >
                  Anterior
                </Button>
                <Button
                  variant='outline'
                  size='sm'
                  disabled={page * size >= data.total}
                  onClick={() => set({ page: page + 1 })}
                >
                  Siguiente
                </Button>
              </div>
            </div>
          </>
        )}
      </QueryBoundary>
      <Detail id={sesion} onClose={() => set({ sesion: undefined })} />
    </div>
  )
}

export function Sesiones() {
  return (
    <Page
      title='Sesiones'
      description='Todas las conversaciones de la captura.'
    >
      <RequireCapture>
        <SesionesContent />
      </RequireCapture>
    </Page>
  )
}
