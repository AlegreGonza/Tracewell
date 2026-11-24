import { type Alert } from '@/lib/api/schemas'
import { SEVERITY_ORDER } from '@/lib/severity'
import { HelpTip } from '@/components/help-tip'
import { SeverityBadge } from '@/components/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { RISK_WEIGHT, riskLevel, riskScore } from './risk'

// Medio círculo: el arco de color llega hasta el puntaje (0-100).
function Gauge({ score, color }: { score: number; color: string }) {
  const a = Math.PI * (1 - score / 100)
  const x = 60 + 50 * Math.cos(a)
  const y = 60 - 50 * Math.sin(a)
  return (
    <svg viewBox='0 0 120 70' className='w-40' aria-hidden='true'>
      <path
        d='M10 60 A50 50 0 0 1 110 60'
        fill='none'
        stroke='var(--muted)'
        strokeWidth='10'
        strokeLinecap='round'
      />
      {score > 0 && (
        <path
          d={`M10 60 A50 50 0 0 1 ${x} ${y}`}
          fill='none'
          stroke={color}
          strokeWidth='10'
          strokeLinecap='round'
        />
      )}
    </svg>
  )
}

export function RiskCard({ alerts }: { alerts: Alert[] }) {
  const score = riskScore(alerts)
  const level = riskLevel(score)
  const top = [...alerts]
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity)
    )
    .slice(0, 5)

  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-1'>
          Puntaje de riesgo <HelpTip topic='riesgo' />
        </CardTitle>
      </CardHeader>
      <CardContent className='flex flex-wrap items-center gap-6'>
        <div className='flex flex-col items-center'>
          <Gauge score={score} color={level.color} />
          <strong className='-mt-6 text-3xl' data-testid='risk-score'>
            {score}
          </strong>
          <span className='text-sm text-muted-foreground'>{level.text}</span>
        </div>
        <ul
          aria-label='Por qué este puntaje'
          className='min-w-0 flex-1 space-y-1'
        >
          {top.map((a, i) => (
            <li
              key={`${a.rule_id}-${i}`}
              className='flex items-center gap-2 text-sm'
            >
              <SeverityBadge severity={a.severity} />
              <span className='truncate'>{a.name}</span>
              <span className='ms-auto font-mono text-xs text-muted-foreground'>
                +{RISK_WEIGHT[a.severity] ?? 5}
              </span>
            </li>
          ))}
          {top.length === 0 && (
            <li className='text-sm text-muted-foreground'>
              Sin alertas: no hay nada que sumar.
            </li>
          )}
        </ul>
      </CardContent>
    </Card>
  )
}
