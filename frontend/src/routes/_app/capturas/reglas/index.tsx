import { createFileRoute } from '@tanstack/react-router'
import { Reglas } from '@/features/reglas'

export const Route = createFileRoute('/_app/capturas/reglas/')({
  component: Reglas,
})
