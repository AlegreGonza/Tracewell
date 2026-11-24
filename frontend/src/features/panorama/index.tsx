import { Link } from '@tanstack/react-router'
import { useAlerts, useStats } from '@/lib/api/queries'
import { useCapture } from '@/context/capture-provider'
import { type Stats } from '@/lib/api/schemas'
import { formatBytes } from '@/lib/format'
import { RequireCapture } from '@/components/empty-capture'
import { HelpTip } from '@/components/help-tip'
import { Page } from '@/components/page'
import { QueryBoundary } from '@/components/query-boundary'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Activity } from './activity'
import { GuidedCase } from './guided-case'
import { Protocols } from './protocols'
import { RiskCard } from './risk-card'
import { TopTalkers } from './top-talkers'

const n = (v: number | undefined) => (v ?? 0).toLocaleString('es-AR')

function StatsCard({ stats, alerts }: { stats: Stats; alerts: number }) {
  const items: [string, string][] = [
    ['Sesiones', n(stats.sessions)],
    ['Paquetes', n(stats.packets)],
    ['Tráfico', formatBytes(stats.bytes)],
    ['Alertas', n(alerts)],
    ['Sin IP (ARP…)', n(stats.non_ip)],
    ['Dañados', n(stats.malformed)],
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1'>
          Resumen <HelpTip topic='resumen' />
        </CardTitle>
      </CardHeader>
      <CardContent className='space-y-3'>
        {stats.truncated && (
          <Alert role='note'>
            <AlertDescription>
              Análisis parcial: se alcanzó el tope de sesiones y se
              descartaron {n(stats.untracked_packets)} paquetes de sesiones
              nuevas. Las cifras no incluyen ese tráfico.
            </AlertDescription>
          </Alert>
        )}
        <dl className='grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6'>
          {items.map(([label, value]) => (
            <div key={label}>
              <dt className='text-xs text-muted-foreground'>{label}</dt>
              <dd className='text-xl font-semibold'>{value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}

function PanoramaContent() {
  const stats = useStats()
  const alerts = useAlerts()
  const { capture } = useCapture()
  const isDemo = /(^|[\\/])demo\.pcap$/.test(capture?.source ?? '')
  return (
    <div className='space-y-4'>
      {isDemo && <GuidedCase />}
      <QueryBoundary query={stats}>
        {(s) => <StatsCard stats={s} alerts={alerts.data?.length ?? 0} />}
      </QueryBoundary>
      <div className='grid gap-4 lg:grid-cols-2'>
        <QueryBoundary query={alerts}>
          {(list) => <RiskCard alerts={list} />}
        </QueryBoundary>
        {stats.data && <Protocols stats={stats.data} />}
      </div>
      <div className='grid gap-4 lg:grid-cols-2'>
        <TopTalkers />
        <Activity />
      </div>
      <p className='text-sm'>
        <Link
          to='/capturas/alertas'
          search={{}}
          className='underline underline-offset-4'
        >
          Ver todas las alertas
        </Link>
      </p>
    </div>
  )
}

export function Panorama() {
  return (
    <Page
      title='Panorama'
      description='Resumen de la captura: riesgo, protocolos y actividad.'
    >
      <RequireCapture>
        <PanoramaContent />
      </RequireCapture>
    </Page>
  )
}
