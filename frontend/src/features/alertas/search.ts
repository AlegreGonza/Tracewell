// Filtros de Alertas en la URL (?severity=high&tactic=Discovery&technique=T1046&alerta=port_scan).
import { z } from 'zod'
import { severitySchema } from '@/lib/api/schemas'

export const alertasSearchSchema = z.object({
  severity: severitySchema.optional().catch(undefined),
  /** Táctica MITRE ATT&CK (por ejemplo "Discovery"). */
  tactic: z.string().max(60).optional().catch(undefined),
  /** Técnica MITRE ATT&CK (por ejemplo "T1046" o "T1568.002"). */
  technique: z.string().max(20).optional().catch(undefined),
  /** Alerta seleccionada para el panel de detalle: rule_id, o rule_id#n si la regla se repite. */
  alerta: z.string().max(64).optional().catch(undefined),
})

