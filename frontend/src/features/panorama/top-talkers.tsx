import { Link } from '@tanstack/react-router'
import { useHosts } from '@/lib/api/queries'
import { formatBytes } from '@/lib/format'
import { HelpTip } from '@/components/help-tip'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const TOP = 5

/** «Quién más habla»: los equipos con más tráfico, con enlace a sus sesiones. */
export function TopTalkers() {
  const { data } = useHosts()
  const hosts = [...(data?.items ?? [])]
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, TOP)
  if (hosts.length === 0) return null
  const max = Math.max(...hosts.map((h) => h.bytes), 1)

  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1'>
          Quién más habla <HelpTip topic='equipos' />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className='space-y-2'>
          {hosts.map((h) => (
            <li
              key={h.ip}
              className='grid grid-cols-[minmax(7rem,auto)_1fr_auto] items-center gap-3 text-sm'
            >
              <Link
                to='/capturas/sesiones'
                search={{ ip: h.ip, page: 1, size: 50 }}
                title={h.name ?? h.owner ?? 'Ver sus sesiones'}
                className='font-mono underline-offset-4 hover:underline'
              >
                {h.ip}
              </Link>
              <span
                className='h-2 rounded-full bg-primary/70'
                style={{ width: `${Math.max(3, (h.bytes / max) * 100)}%` }}
                aria-hidden='true'
              />
              <span className='text-muted-foreground'>
                {formatBytes(h.bytes)}
                <span className='sr-only'> de {h.name ?? h.owner ?? h.ip}</span>
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}
