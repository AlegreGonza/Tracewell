import { createFileRoute, notFound } from '@tanstack/react-router'
import { NETWORK_SECTIONS } from '@/config/support-sections'
import { SoporteRed } from '@/features/soporte-red'

// Una sección que no existe da la pantalla 404 en vez de una pantalla vacía.
export const Route = createFileRoute('/_app/soporte/red/$seccion/')({
  beforeLoad: ({ params }) => {
    if (!NETWORK_SECTIONS.some((s) => s.id === params.seccion)) throw notFound()
  },
  component: Pantalla,
})

function Pantalla() {
  const { seccion } = Route.useParams()
  return <SoporteRed seccion={seccion} />
}
