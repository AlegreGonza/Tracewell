import { cn } from '@/lib/utils'

type MeterProps = {
  label: string
  percent: number | null | undefined
  detail?: string | null
  /** true: un valor alto es bueno (p. ej. la señal Wi-Fi). Por defecto, alto es malo. */
  goodHigh?: boolean
}

function meterLevel(p: number, goodHigh: boolean): 'ok' | 'mid' | 'high' {
  if (goodHigh) return p < 40 ? 'high' : p < 70 ? 'mid' : 'ok'
  return p >= 90 ? 'high' : p >= 75 ? 'mid' : 'ok'
}

const FILL = { ok: 'bg-chart-2', mid: 'bg-sev-medium', high: 'bg-sev-critical' }

/** Barra con el porcentaje en texto (el color solo refuerza: el número siempre está). */
export function Meter({ label, percent, detail, goodHigh = false }: MeterProps) {
  const known = typeof percent === 'number' && Number.isFinite(percent)
  const p = known ? Math.max(0, Math.min(100, percent)) : 0
  const level = meterLevel(p, goodHigh)
  return (
    <div className='space-y-1'>
      <div className='flex items-baseline justify-between gap-2 text-sm'>
        <span>{label}</span>
        <span className='font-mono tabular-nums'>
          {known ? `${p.toFixed(1)} %` : '—'}
        </span>
      </div>
      <div
        role='meter'
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={p}
        data-level={level}
        className='h-2 w-full overflow-hidden rounded-full bg-muted'
      >
        <div
          className={cn('h-full rounded-full', FILL[level])}
          style={{ width: `${p}%` }}
        />
      </div>
      {detail && <p className='text-xs text-muted-foreground'>{detail}</p>}
    </div>
  )
}
