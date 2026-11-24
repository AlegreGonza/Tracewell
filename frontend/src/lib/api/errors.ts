// Mensajes de error de la API y aviso global (toast) para queries y mutations.
import { toast } from 'sonner'
import { ApiError, ApiSchemaError } from './client'

/** Texto legible de cualquier error; el `detail` del backend se muestra tal cual (403 incluido). */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof ApiSchemaError) {
    return error.message
  }
  if (error instanceof Error && error.message) return error.message
  return 'Ocurrió un error inesperado.'
}

/** Los abortos (cambio de pantalla, cancelación) no son errores para el usuario. */
export function isAbort(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: string }).name === 'AbortError'
  )
}

/** Ids de toast por mensaje: el mismo error repetido no apila avisos. */
export function notifyError(error: unknown): void {
  if (isAbort(error)) return
  const message = errorMessage(error)
  toast.error(message, { id: `api-error:${message}` })
}
