import { createFileRoute } from '@tanstack/react-router'
import { Alertas } from '@/features/alertas'
import { alertasSearchSchema } from '@/features/alertas/search'

// Los filtros viven en la URL y se validan con zod (ver features/alertas/search.ts)
export const Route = createFileRoute('/_app/capturas/alertas/')({
  validateSearch: alertasSearchSchema,
  component: Alertas,
})
