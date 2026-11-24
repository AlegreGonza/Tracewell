import { type Alert, type Severity } from '@/lib/api/schemas'

/** Peso de cada alerta en el puntaje, por severidad. */
export const RISK_WEIGHT: Record<Severity, number> = {
  critical: 35,
  high: 25,
  medium: 12,
  low: 5,
}

export function riskScore(alerts: Alert[]) {
  const sum = alerts.reduce((acc, a) => acc + (RISK_WEIGHT[a.severity] ?? 5), 0)
  return Math.min(100, sum)
}

export function riskLevel(score: number) {
  if (score >= 70) return { text: 'Alto', color: 'var(--sev-critical)' }
  if (score >= 40) return { text: 'Medio', color: 'var(--sev-high)' }
  if (score > 0) return { text: 'Bajo', color: 'var(--sev-medium)' }
  return { text: 'Sin alertas', color: 'var(--chart-2)' }
}
