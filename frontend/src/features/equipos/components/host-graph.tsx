import { useMemo, useState } from 'react'
import { useGraph } from '@/lib/api/queries'
import { type z } from 'zod'
import { type graphNodeSchema } from '@/lib/api/schemas'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { QueryBoundary } from '@/components/query-boundary'
import { CardSkeleton } from '@/components/skeletons'
import { hostName, kindLabel, SOURCE_NOTE } from './labels'

type GraphNode = z.infer<typeof graphNodeSchema>
const W = 1000
const H = 560
const CX = W / 2
const CY = H / 2

type Pos = { x: number; y: number; anchor: 'start' | 'end' | 'middle' }

function ring(items: GraphNode[], rx: number, ry: number, out: Record<string, Pos>) {
  items.forEach((node, i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / items.length
    const cos = Math.cos(angle)
    out[node.ip] = {
      x: CX + rx * cos,
      y: CY + ry * Math.sin(angle),
      anchor: Math.abs(cos) < 0.2 ? 'middle' : cos > 0 ? 'start' : 'end',
    }
  })
}

/** «Telaraña»: tu red en el centro y el resto de los equipos en un anillo alrededor. */
function layoutGraph(nodes: GraphNode[]): Record<string, Pos> {
  const pos: Record<string, Pos> = {}
  const inner = nodes.filter((x) => x.kind === 'interna')
  const outer = nodes.filter((x) => x.kind !== 'interna')
  if (inner.length === 1) pos[inner[0].ip] = { x: CX, y: CY, anchor: 'middle' }
  else ring(inner, 120, 85, pos)
  ring(outer, 360, 225, pos)
  return pos
}

const short = (t: string, max = 22) => (t.length > max ? `${t.slice(0, max - 1)}…` : t)

function GraphSvg({
  nodes,
  edges,
  onOpen,
}: {
  nodes: GraphNode[]
  edges: { a: string; b: string; bytes: number; sessions: number; protocols: string[] }[]
  onOpen: (ip: string) => void
}) {
  const [hover, setHover] = useState<string | null>(null)
  const pos = useMemo(() => layoutGraph(nodes), [nodes])
  const maxBytes = useMemo(() => Math.max(...edges.map((e) => e.bytes), 1), [edges])
  const neighbors = useMemo(() => {
    const set = new Set<string>()
    for (const e of edges) {
      if (e.a === hover) set.add(e.b)
      else if (e.b === hover) set.add(e.a)
    }
    return set
  }, [edges, hover])

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      role='group'
      aria-label={`Grafo de ${nodes.length} equipos y ${edges.length} conversaciones entre ellos`}
      className='h-auto w-full text-foreground'
    >
      {edges.map((e) => {
        const a = pos[e.a]
        const b = pos[e.b]
        if (!a || !b) return null
        const active = hover !== null && (e.a === hover || e.b === hover)
        return (
          <line
            key={`${e.a}|${e.b}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            strokeWidth={1 + 5 * Math.sqrt(e.bytes / maxBytes)}
            className={cn('stroke-muted-foreground/40', active && 'stroke-primary')}
          >
            <title>
              {`${e.a} ↔ ${e.b} · ${e.sessions} sesión(es) · ${formatBytes(e.bytes)} · ${e.protocols.join(', ')}`}
            </title>
          </line>
        )
      })}
      {nodes.map((node) => {
        const p = pos[node.ip]
        if (!p) return null
        const flagged = node.alerts > 0 || node.ioc
        const nm = hostName(node)
        const label = nm.source ? nm.text : node.ip
        const dim = hover !== null && hover !== node.ip && !neighbors.has(node.ip)
        const dx = p.anchor === 'start' ? 22 : p.anchor === 'end' ? -22 : 0
        const dy = p.anchor === 'middle' ? (p.y < CY ? -24 : 32) : 4
        return (
          <g
            key={node.ip}
            transform={`translate(${p.x}, ${p.y})`}
            tabIndex={0}
            role='button'
            aria-label={`${label} (${node.ip}). Ver su perfil`}
            className={cn('cursor-pointer outline-none', dim && 'opacity-30')}
            onMouseEnter={() => setHover(node.ip)}
            onMouseLeave={() => setHover(null)}
            onFocus={() => setHover(node.ip)}
            onBlur={() => setHover(null)}
            onClick={() => onOpen(node.ip)}
            onKeyDown={(ev) => {
              if (ev.key === 'Enter' || ev.key === ' ') {
                ev.preventDefault()
                onOpen(node.ip)
              }
            }}
          >
            <circle
              r={node.kind === 'interna' ? 16 : 12}
              strokeWidth={2}
              className={cn(
                'fill-card',
                flagged ? 'stroke-sev-high' : 'stroke-primary',
                node.kind === 'publica' && 'stroke-muted-foreground'
              )}
            />
            <text
              x={dx}
              y={dy}
              textAnchor={p.anchor}
              className={cn(
                'fill-current text-[13px]',
                nm.source !== 'captura' && nm.source !== null && 'fill-muted-foreground'
              )}
            >
              {short(label)}
              {flagged && (
                <tspan dx='6' className='fill-sev-high font-semibold'>
                  {node.ioc ? 'IOC' : `! ${node.alerts}`}
                </tspan>
              )}
            </text>
            <title>
              {[
                node.ip,
                node.role_label ?? kindLabel(node.kind),
                nm.source ? SOURCE_NOTE[nm.source] : null,
                `${node.sessions} sesión(es)`,
                formatBytes(node.bytes),
              ]
                .filter(Boolean)
                .join(' · ')}
            </title>
          </g>
        )
      })}
    </svg>
  )
}

/** Mapa de quién habla con quién; el detalle accesible está en la tabla y en el perfil. */
export function HostGraph({ onOpen }: { onOpen: (ip: string) => void }) {
  const query = useGraph()
  return (
    <QueryBoundary
      query={query}
      skeleton={<CardSkeleton />}
      isEmpty={(d) => d.nodes.length === 0}
      empty={<p className='text-sm text-muted-foreground'>No hay conversaciones para dibujar.</p>}
    >
      {(data) => (
        <div className='space-y-2'>
          <GraphSvg nodes={data.nodes} edges={data.edges} onOpen={onOpen} />
          <p className='text-xs text-muted-foreground'>
            Tu red está en el centro y el resto de los equipos, alrededor. El grosor de la línea es
            el tráfico. Elegí un equipo (clic o Enter) para ver su perfil. Los nombres en gris son
            una pista por el dueño del rango de IP; el nombre real aparece cuando la captura lo
            contiene.
            {data.truncated ? ' Se muestran solo los de más tráfico.' : ''}
          </p>
        </div>
      )}
    </QueryBoundary>
  )
}
