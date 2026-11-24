import { createFileRoute } from '@tanstack/react-router'
import { Remoto } from '@/features/remoto'

export const Route = createFileRoute('/_app/capturas/remoto/')({
  component: Remoto,
})
