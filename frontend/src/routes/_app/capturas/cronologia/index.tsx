import { createFileRoute } from '@tanstack/react-router'
import { Cronologia } from '@/features/cronologia'

export const Route = createFileRoute('/_app/capturas/cronologia/')({
  component: Cronologia,
})
