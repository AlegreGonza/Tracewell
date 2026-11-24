import { createFileRoute } from '@tanstack/react-router'
import { Sesiones } from '@/features/sesiones'
import { sesionesSearchSchema } from '@/features/sesiones/search'

// Los filtros viven en la URL y se validan con zod (ver features/sesiones/search.ts)
export const Route = createFileRoute('/_app/capturas/sesiones/')({
  validateSearch: sesionesSearchSchema,
  component: Sesiones,
})
