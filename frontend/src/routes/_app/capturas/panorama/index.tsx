import { createFileRoute } from '@tanstack/react-router'
import { Panorama } from '@/features/panorama'

export const Route = createFileRoute('/_app/capturas/panorama/')({
  component: Panorama,
})
