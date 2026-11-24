// Lista de reglas con MITRE (si el backend lo informa) y vista previa sin toast por tecla.
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { z } from 'zod'
import { api, ApiError, type RuleBody } from '@/lib/api/client'
import { errorMessage } from '@/lib/api/errors'
import { severitySchema } from '@/lib/api/schemas'
import { useCapture } from '@/context/capture-provider'

const mitreSchema = z.looseObject({
  technique: z.string().nullish(),
  name: z.string().nullish(),
  tactic: z.string().nullish(),
})

const ruleRowSchema = z.looseObject({
  id: z.string(),
  name: z.string(),
  severity: severitySchema,
  detector: z.string().nullish(),
  custom: z.boolean().default(false),
  mitre: mitreSchema.nullish(),
  mitre_tactic: z.string().nullish(),
  mitre_technique: z.string().nullish(),
  mitre_name: z.string().nullish(),
})
export type Rule = z.infer<typeof ruleRowSchema>

type MitreInfo = { tactic?: string; technique?: string; name?: string }

/** MITRE de una regla, venga anidado (`mitre`) o plano (`mitre_*`). */
export function mitreOf(rule: Rule): MitreInfo {
  const m = rule.mitre
  return {
    tactic: m?.tactic ?? rule.mitre_tactic ?? undefined,
    technique: m?.technique ?? rule.mitre_technique ?? undefined,
    name: m?.name ?? rule.mitre_name ?? undefined,
  }
}

/** GET /api/rules con los campos MITRE opcionales (el esquema compartido los deja pasar). */
export function useRuleList() {
  return useQuery({
    queryKey: ['rules', 'lista'],
    queryFn: async ({ signal }) => {
      const data = await api.rules(signal)
      const rows = z.array(ruleRowSchema).safeParse(data.items)
      return {
        items: rows.success ? rows.data : ([] as Rule[]),
        example: data.example ?? null,
      }
    },
  })
}

/** Vista previa en vivo: el error se muestra en pantalla, no como toast por cada tecla. */
export function useRulePreview(body: RuleBody | null) {
  const { generation } = useCapture()
  return useQuery({
    queryKey: ['rules', 'preview', generation, body],
    queryFn: ({ signal }) => api.previewRule(body as RuleBody, signal),
    enabled: body !== null,
    placeholderData: keepPreviousData,
    retry: false,
    staleTime: 30_000,
    meta: { silent: true },
  })
}

/** Mensaje claro para un fallo al guardar o previsualizar (403, 409, 422). */
export function ruleErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.isForbidden)
      return `No hay permiso para escribir en la carpeta de reglas. ${error.detail}`
    if (error.status === 409)
      return `Ya existe una regla con ese id. Cambiá el nombre o el id. ${error.detail}`
    if (error.isValidation) return `La regla no es válida: ${error.detail}`
  }
  return errorMessage(error)
}
