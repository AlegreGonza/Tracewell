import { RequireCapture } from '@/components/empty-capture'
import { Page } from '@/components/page'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DnsTab } from './dns-tab'
import { HttpTab } from './http-tab'

export function Trafico() {
  return (
    <Page title='DNS y HTTP' description='Nombres consultados y sitios web visitados.'>
      <RequireCapture>
        <Tabs defaultValue='dns'>
          <TabsList>
            <TabsTrigger value='dns'>DNS</TabsTrigger>
            <TabsTrigger value='http'>HTTP</TabsTrigger>
          </TabsList>
          <TabsContent value='dns' className='mt-3'>
            <DnsTab />
          </TabsContent>
          <TabsContent value='http' className='mt-3'>
            <HttpTab />
          </TabsContent>
        </Tabs>
      </RequireCapture>
    </Page>
  )
}
