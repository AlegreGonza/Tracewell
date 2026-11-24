import { useCallback, useState } from 'react'
import { useHosts } from '@/lib/api/queries'
import { RequireCapture } from '@/components/empty-capture'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { HostGraph } from './components/host-graph'
import { HostProfile } from './components/host-profile'
import { HostsTable } from './components/hosts-table'
import { MacGroups } from './components/mac-groups'

function EquiposContent() {
  const query = useHosts()
  const [selected, setSelected] = useState<string | null>(null)
  const open = useCallback((ip: string) => setSelected(ip), [])
  const close = useCallback(() => setSelected(null), [])
  const hosts = query.data?.items ?? []
  const host = hosts.find((h) => h.ip === selected) ?? null

  return (
    <QueryBoundary
      query={query}
      isEmpty={(d) => d.items.length === 0}
      empty={
        <p className='text-sm text-muted-foreground'>
          La captura no tiene equipos que mostrar.
        </p>
      }
    >
      {(data) => (
        <>
          <p className='mb-3 text-sm text-muted-foreground'>
            {data.total.toLocaleString('es-AR')} IP distintas.
          </p>
          <Tabs defaultValue='tabla'>
            <TabsList>
              <TabsTrigger value='tabla'>Tabla</TabsTrigger>
              <TabsTrigger value='mapa'>Mapa</TabsTrigger>
              <TabsTrigger value='mac'>Por MAC</TabsTrigger>
            </TabsList>
            <TabsContent value='tabla' className='mt-3'>
              <HostsTable hosts={data.items} onOpen={open} />
            </TabsContent>
            <TabsContent value='mapa' className='mt-3'>
              <HostGraph onOpen={open} />
            </TabsContent>
            <TabsContent value='mac' className='mt-3'>
              <MacGroups onOpen={open} />
            </TabsContent>
          </Tabs>
          <HostProfile host={host} onClose={close} onOpen={open} />
        </>
      )}
    </QueryBoundary>
  )
}

export function Equipos() {
  return (
    <Page title='Equipos' description='Quién habló con quién en la captura.'>
      <RequireCapture>
        <EquiposContent />
      </RequireCapture>
    </Page>
  )
}
