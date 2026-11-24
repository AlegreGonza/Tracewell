// Filtros de Sesiones en la URL (?protocol=TCP&ip=10.0.0.1&port=443&page=2&size=50&sesion=7).
// `.catch()` descarta un valor inválido en vez de romper la pantalla.
import { z } from 'zod'

export const sesionesSearchSchema = z.object({
  protocol: z.string().max(10).optional().catch(undefined),
  ip: z.string().max(64).optional().catch(undefined),
  port: z.number().int().min(0).max(65535).optional().catch(undefined),
  page: z.number().int().min(1).catch(1),
  size: z.number().int().min(10).max(500).catch(50),
  /** Sesión abierta en el panel lateral. */
  sesion: z.number().int().min(0).optional().catch(undefined),
})
