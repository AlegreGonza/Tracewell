import { type Host } from '@/lib/api/schemas'

const KIND_LABEL: Record<string, string> = {
  interna: 'Interna',
  publica: 'Pública',
  multicast: 'Multicast',
}

export const kindLabel = (kind: string) => KIND_LABEL[kind] ?? kind

/** Tipo en texto: la etiqueta de rol del backend o, si falta, la clase de dirección. */
export const hostType = (h: Pick<Host, 'role_label' | 'kind'>) =>
  h.role_label || kindLabel(h.kind)

export const SOURCE_NOTE = {
  captura: 'Nombre sacado de la propia captura (DNS o TLS)',
  rango:
    'Dueño del rango de IP según una tabla local: es una pista, no una prueba (la nube se alquila)',
  especial: 'Dirección especial de la red',
} as const

/** Nombre a mostrar de un equipo y de dónde sale (la captura, el rango de IP o una nota). */
export function hostName(h: {
  ip: string
  name?: string | null
  owner?: string | null
  note?: string | null
}): { text: string; source: keyof typeof SOURCE_NOTE | null } {
  if (h.name) return { text: h.name, source: 'captura' }
  if (h.owner) return { text: h.owner, source: 'rango' }
  if (h.note) return { text: h.note.split(' (')[0], source: 'especial' }
  return { text: h.ip, source: null }
}
