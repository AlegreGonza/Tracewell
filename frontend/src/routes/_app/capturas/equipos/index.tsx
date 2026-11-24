import { createFileRoute } from '@tanstack/react-router'
import { Equipos } from '@/features/equipos'

export const Route = createFileRoute('/_app/capturas/equipos/')({
  component: Equipos,
})
