// Nombre corto de cada pista sobre un programa (el motivo largo viene del backend).
export const HINT_LABEL: Record<string, string> = {
  carpeta_temporal: 'Carpeta temporal',
  nombre_de_windows: 'Nombre de Windows en otra carpeta',
  borrado: 'Archivo borrado',
}

/** Etiqueta de una pista; un código desconocido se muestra tal cual. */
export function hintLabel(code: string): string {
  return Object.hasOwn(HINT_LABEL, code) ? HINT_LABEL[code] : code
}
