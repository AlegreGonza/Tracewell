import { type Severity } from '@/lib/api/schemas'

export const SEVERITY_LABEL: Record<Severity, string> = {
  low: 'Baja',
  medium: 'Media',
  high: 'Alta',
  critical: 'Crítica',
}

/** Orden de menor a mayor gravedad (para ordenar o recorrer). */
export const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical']
