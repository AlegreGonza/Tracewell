import { ExternalLink } from 'lucide-react'
import { type Alert } from '@/lib/api/schemas'
import { cn } from '@/lib/utils'
import { HelpTip } from '@/components/help-tip'
import { SeverityBadge } from '@/components/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  buildAttackColumns,
  NO_TACTIC,
  NO_TECHNIQUE,
  techniqueUrl,
} from '../attack'

type AttackMapProps = {
  alerts: readonly Alert[]
  tactic?: string
  technique?: string
  /** Clic en una táctica o técnica: filtra la tabla de alertas (null = quitar el filtro). */
  onSelect: (filter: { tactic?: string; technique?: string } | null) => void
}

/** Mapa MITRE ATT&CK: una columna por táctica, con las técnicas que dispararon alertas. */
export function AttackMap({
  alerts,
  tactic,
  technique,
  onSelect,
}: AttackMapProps) {
  const columns = buildAttackColumns(alerts)
  const active = columns.filter((c) => c.alerts > 0).length
  return (
    <Card aria-labelledby='attack-title'>
      <CardHeader className='flex-row items-center justify-between gap-2'>
        <CardTitle id='attack-title' className='flex items-center gap-1.5'>
          Mapa MITRE ATT&amp;CK
          <HelpTip topic='attack' />
        </CardTitle>
      </CardHeader>
      <CardContent className='space-y-3'>
        <div
          role='region'
          aria-label='Tácticas y técnicas MITRE ATT&CK (se desplaza horizontalmente)'
          tabIndex={0}
          className='-mx-1 overflow-x-auto px-1 pb-2 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
        >
          <ol className='grid auto-cols-[minmax(10.5rem,1fr)] grid-flow-col gap-2'>
            {columns.map((c) => {
              const selectedTactic = !!tactic && tactic === c.key
              return (
                <li
                  key={c.key || 'sin-tactica'}
                  data-hit={c.alerts > 0 || undefined}
                  className={cn(
                    'flex flex-col gap-2 rounded-lg border p-2',
                    c.alerts > 0 ? 'bg-muted/50' : 'border-dashed',
                    selectedTactic && 'ring-2 ring-ring'
                  )}
                >
                  <div>
                    {c.key !== NO_TACTIC && c.alerts > 0 ? (
                      <button
                        type='button'
                        aria-pressed={selectedTactic}
                        onClick={() =>
                          onSelect(selectedTactic ? null : { tactic: c.key })
                        }
                        className='text-start text-sm font-semibold hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
                      >
                        {c.label}
                      </button>
                    ) : (
                      <span className='text-sm font-semibold'>{c.label}</span>
                    )}
                    <p className='text-xs text-muted-foreground'>
                      {c.known ? c.key : 'Fuera del catálogo'}
                    </p>
                    <p className='mt-1 text-xs text-muted-foreground'>
                      {c.gloss}
                    </p>
                  </div>
                  {c.techniques.length === 0 ? (
                    <p
                      className='text-xs text-muted-foreground'
                      aria-label='Sin alertas en esta táctica'
                    >
                      —
                    </p>
                  ) : (
                    <ul className='flex flex-col gap-1.5'>
                      {c.techniques.map((t) => {
                        const selected = !!technique && technique === t.id
                        return (
                          <li
                            key={t.id || 'sin-tecnica'}
                            className={cn(
                              'rounded-md border bg-card p-1.5 text-xs',
                              selected && 'ring-2 ring-ring'
                            )}
                          >
                            <div className='flex items-center justify-between gap-1'>
                              {t.id !== NO_TECHNIQUE ? (
                                <a
                                  href={techniqueUrl(t.id)}
                                  target='_blank'
                                  rel='noopener noreferrer'
                                  className='inline-flex items-center gap-0.5 font-mono font-medium underline-offset-2 hover:underline'
                                  aria-label={`${t.id}: abrir en attack.mitre.org (pestaña nueva)`}
                                >
                                  {t.id}
                                  <ExternalLink
                                    className='size-3'
                                    aria-hidden='true'
                                  />
                                </a>
                              ) : (
                                <span className='text-muted-foreground'>
                                  Sin técnica
                                </span>
                              )}
                              <SeverityBadge
                                severity={t.severity}
                                className='px-1.5 py-0 text-[0.65rem]'
                              />
                            </div>
                            <button
                              type='button'
                              aria-pressed={selected}
                              onClick={() =>
                                onSelect(
                                  selected
                                    ? null
                                    : t.id === NO_TECHNIQUE
                                      ? { tactic: c.key || undefined }
                                      : { technique: t.id }
                                )
                              }
                              className='mt-1 block w-full text-start hover:underline focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-hidden'
                              aria-label={`Filtrar alertas por ${t.name} (${t.count})`}
                            >
                              <span>{t.name}</span>{' '}
                              <span className='text-muted-foreground'>
                                ×{t.count}
                              </span>
                            </button>
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </li>
              )
            })}
          </ol>
        </div>
        <p className='text-xs text-muted-foreground'>
          {alerts.length === 0
            ? 'Sin alertas: ninguna táctica se iluminó.'
            : `${active} táctica(s) con actividad. Las columnas vacías no significan que no haya pasado nada: solo que ninguna regla lo vio.`}
        </p>
      </CardContent>
    </Card>
  )
}
