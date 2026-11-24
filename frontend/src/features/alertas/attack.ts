// Lógica pura del mapa MITRE ATT&CK: tácticas canónicas, agrupación de alertas y enlaces.
import { type Alert, type Severity } from '@/lib/api/schemas'
import { SEVERITY_ORDER } from '@/lib/severity'

type Tactic = {
  /** Nombre en inglés, tal como lo emite el backend en `mitre_tactic`. */
  name: string
  label: string
  /** Explicación didáctica. */
  gloss: string
}

/** Las 9 tácticas que se pueden ver en el tráfico de red, en el orden de ATT&CK. */
const TACTICS: readonly Tactic[] = [
  {
    name: 'Reconnaissance',
    label: 'Reconocimiento',
    gloss: 'El atacante investiga a la víctima antes de atacar.',
  },
  {
    name: 'Initial Access',
    label: 'Acceso inicial',
    gloss: 'Intenta entrar por primera vez a la red.',
  },
  {
    name: 'Credential Access',
    label: 'Acceso a credenciales',
    gloss: 'Roba o adivina usuarios y contraseñas.',
  },
  {
    name: 'Discovery',
    label: 'Exploración',
    gloss: 'Mira qué equipos y servicios hay dentro de la red.',
  },
  {
    name: 'Lateral Movement',
    label: 'Movimiento lateral',
    gloss: 'Salta de un equipo a otros de la misma red.',
  },
  {
    name: 'Collection',
    label: 'Recolección',
    gloss: 'Junta los datos que le interesan antes de sacarlos.',
  },
  {
    name: 'Command and Control',
    label: 'Comando y control',
    gloss: 'Recibe órdenes desde un servidor de afuera.',
  },
  {
    name: 'Exfiltration',
    label: 'Exfiltración',
    gloss: 'Saca los datos de la red.',
  },
  {
    name: 'Impact',
    label: 'Impacto',
    gloss: 'Daña, bloquea o interrumpe sistemas y datos.',
  },
]

/** Clave de la columna para alertas sin táctica. */
export const NO_TACTIC = ''
/** Clave de la técnica para alertas sin técnica. */
export const NO_TECHNIQUE = ''

export const severityRank = (s: Severity | string | null | undefined) =>
  SEVERITY_ORDER.indexOf(s as Severity) + 1

/** https://attack.mitre.org/techniques/T1046/ (subtécnica: /T1568/002/). */
export function techniqueUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
}

type TechniqueGroup = {
  id: string
  name: string
  count: number
  severity: Severity
}

type TacticColumn = {
  /** Clave de filtro: el nombre en inglés ('' = sin táctica). */
  key: string
  label: string
  gloss: string
  techniques: TechniqueGroup[]
  /** Cantidad de alertas de la columna. */
  alerts: number
  known: boolean
}

/** Nombre legible de una técnica: las subtécnicas llegan como «Padre: Hija». */
function techniqueName(name: string | null | undefined, id: string) {
  return name?.trim() || id || 'Sin técnica'
}

/** Agrupa las alertas por táctica y técnica; una táctica desconocida no se pierde. */
export function buildAttackColumns(alerts: readonly Alert[]): TacticColumn[] {
  const byTactic = new Map<string, Map<string, TechniqueGroup>>()
  for (const a of alerts) {
    const tactic = a.mitre_tactic ?? NO_TACTIC
    const id = a.mitre_technique ?? NO_TECHNIQUE
    const techniques = byTactic.get(tactic) ?? new Map<string, TechniqueGroup>()
    byTactic.set(tactic, techniques)
    const t = techniques.get(id) ?? {
      id,
      name: techniqueName(a.mitre_name, id),
      count: 0,
      severity: a.severity,
    }
    techniques.set(id, t)
    t.count += 1
    if (severityRank(a.severity) > severityRank(t.severity)) {
      t.severity = a.severity
    }
  }

  const build = (
    key: string,
    label: string,
    gloss: string,
    known: boolean
  ): TacticColumn => {
    const techniques = [...(byTactic.get(key)?.values() ?? [])].sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        b.count - a.count ||
        a.id.localeCompare(b.id)
    )
    return {
      key,
      label,
      gloss,
      techniques,
      alerts: techniques.reduce((n, t) => n + t.count, 0),
      known,
    }
  }

  const canonical = new Set(TACTICS.map((t) => t.name))
  const columns = TACTICS.map((t) => build(t.name, t.label, t.gloss, true))
  for (const key of byTactic.keys()) {
    if (canonical.has(key)) continue
    columns.push(
      key === NO_TACTIC
        ? build(key, 'Sin táctica', 'Alertas cuya regla no declara táctica.', false)
        : build(key, key, 'Táctica que Tracewell no conoce todavía.', false)
    )
  }
  return columns
}

/** Cada alerta se identifica por su regla (y un #n si la regla se repite). */
export function alertKeys(alerts: readonly Alert[]): string[] {
  const seen = new Map<string, number>()
  return alerts.map((a) => {
    const n = seen.get(a.rule_id) ?? 0
    seen.set(a.rule_id, n + 1)
    return n === 0 ? a.rule_id : `${a.rule_id}#${n}`
  })
}
