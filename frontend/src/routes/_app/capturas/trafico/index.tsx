import { createFileRoute } from '@tanstack/react-router'
import { Trafico } from '@/features/trafico'

export const Route = createFileRoute('/_app/capturas/trafico/')({
  component: Trafico,
})
