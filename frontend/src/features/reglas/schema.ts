// Formulario de la regla: validación (zod) y paso al cuerpo que espera la API.
import { z } from 'zod'
import { type RuleBody } from '@/lib/api/client'

/** Tácticas MITRE ATT&CK canónicas que acepta el motor de reglas. */
export const TACTICS = [
  'Reconnaissance',
  'Initial Access',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const

export const SEVERITY_OPTIONS = [
  { value: 'low', label: 'Baja' },
  { value: 'medium', label: 'Media' },
  { value: 'high', label: 'Alta' },
  { value: 'critical', label: 'Crítica' },
] as const

export const PROTOCOL_OPTIONS = [
  { value: 'any', label: 'Cualquiera' },
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
] as const

const IP_OR_NET = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/
const IP_MSG = 'Una IP o red (ej. 10.0.0.0/8)'

const integer = (min: number, max: number, label: string) =>
  z
    .string()
    .trim()
    .regex(/^\d+$/, `${label}: escribí un número entero`)
    .refine(
      (v) => Number(v) >= min && Number(v) <= max,
      `${label}: entre ${min} y ${max.toLocaleString('es-AR')}`
    )

const ipOrNet = z
  .string()
  .trim()
  .refine((v) => v === '' || IP_OR_NET.test(v), IP_MSG)

export const ruleFormSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'El nombre es obligatorio')
    .max(80, 'El nombre admite hasta 80 caracteres'),
  id: z
    .string()
    .trim()
    .refine(
      (v) => v === '' || /^[a-z][a-z0-9_]{2,39}$/.test(v),
      'Empezá con una letra minúscula; 3 a 40 letras minúsculas, números o _'
    ),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  description: z
    .string()
    .trim()
    .max(500, 'La descripción admite hasta 500 caracteres'),
  protocol: z.enum(['any', 'tcp', 'udp']),
  src_ip: ipOrNet,
  dst_ip: ipOrNet,
  port: integer(0, 65535, 'Puerto'),
  min_events: integer(2, 1_000_000, 'Eventos'),
  window_seconds: z
    .string()
    .trim()
    .refine(
      (v) => v !== '' && Number.isFinite(Number(v)) && Number(v) > 0,
      'Ventana: un número mayor que 0'
    ),
  mitre_tactic: z
    .string()
    .refine(
      (v) => v === '' || (TACTICS as readonly string[]).includes(v),
      'Elegí una de las tácticas de la lista'
    ),
  mitre_technique: z
    .string()
    .trim()
    .refine(
      (v) => v === '' || /^T\d{4}(\.\d{3})?$/.test(v),
      'Formato T1046 o T1568.002'
    ),
  mitre_name: z.string().trim().max(100, 'Hasta 100 caracteres'),
})

export type RuleFormValues = z.infer<typeof ruleFormSchema>

export const EMPTY_FORM: RuleFormValues = {
  name: '',
  id: '',
  severity: 'medium',
  description: '',
  protocol: 'any',
  src_ip: '',
  dst_ip: '',
  port: '0',
  min_events: '20',
  window_seconds: '60',
  mitre_tactic: '',
  mitre_technique: '',
  mitre_name: '',
}

/** Valores del formulario (texto) al cuerpo tipado de la API; omite lo vacío. */
export function toBody(v: RuleFormValues): RuleBody {
  const technique = v.mitre_technique.trim()
  const mitreName = v.mitre_name.trim()
  return {
    name: v.name.trim(),
    severity: v.severity,
    description: v.description.trim(),
    protocol: v.protocol,
    src_ip: v.src_ip.trim(),
    dst_ip: v.dst_ip.trim(),
    port: Number(v.port),
    min_events: Number(v.min_events),
    window_seconds: Number(v.window_seconds),
    ...(v.id.trim() ? { id: v.id.trim() } : {}),
    ...(v.mitre_tactic ? { mitre_tactic: v.mitre_tactic } : {}),
    ...(technique ? { mitre_technique: technique } : {}),
    ...(mitreName ? { mitre_name: mitreName } : {}),
  }
}

/** El ejemplo del backend (números) al formulario (texto). */
export function exampleToForm(
  example: Record<string, unknown>
): RuleFormValues {
  const out: Record<string, string> = { ...EMPTY_FORM }
  for (const [k, val] of Object.entries(example)) {
    if (k in EMPTY_FORM && val != null) out[k] = String(val)
  }
  return out as RuleFormValues
}

/** Cuerpo para la vista previa: null si el formulario todavía no valida. */
export function bodyIfValid(values: RuleFormValues): RuleBody | null {
  const parsed = ruleFormSchema.safeParse(values)
  return parsed.success ? toBody(parsed.data) : null
}
