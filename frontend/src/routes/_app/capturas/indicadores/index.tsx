import { createFileRoute } from '@tanstack/react-router'
import { Indicadores } from '@/features/indicadores'

export const Route = createFileRoute('/_app/capturas/indicadores/')({
  component: Indicadores,
})
