// Descargas con ticket de un solo uso: el token nunca viaja en la URL de un <a download>.
type SiemFormat = 'ecs' | 'cef' | 'syslog'
export type SiemSeverity = 'all' | 'low' | 'medium' | 'high' | 'critical'

export const SIEM_FORMATS: { value: SiemFormat; label: string; hint: string }[] =
  [
    { value: 'ecs', label: 'Elastic (ECS, NDJSON)', hint: 'Un JSON por línea' },
    { value: 'cef', label: 'ArcSight CEF', hint: 'Texto plano' },
    { value: 'syslog', label: 'Syslog RFC 5424', hint: 'Con CEF adentro' },
  ]

export const SIEM_SEVERITIES: { value: SiemSeverity; label: string }[] = [
  { value: 'all', label: 'Todas las severidades' },
  { value: 'low', label: 'Baja o mayor' },
  { value: 'medium', label: 'Media o mayor' },
  { value: 'high', label: 'Alta o mayor' },
  { value: 'critical', label: 'Solo críticas' },
]

/** URL (sin ticket) de la exportación SIEM. */
export function siemUrl(format: SiemFormat, minSeverity: SiemSeverity): string {
  const q = new URLSearchParams({ format })
  if (minSeverity !== 'all') q.set('min_severity', minSeverity)
  return `/api/export/siem?${q.toString()}`
}

/** Dispara la descarga de una URL ya con ticket (el nombre lo pone Content-Disposition). */
export function triggerDownload(url: string): void {
  const a = document.createElement('a')
  a.href = url
  a.rel = 'noopener'
  a.download = ''
  document.body.appendChild(a)
  a.click()
  a.remove()
}
