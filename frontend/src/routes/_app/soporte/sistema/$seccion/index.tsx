import { createFileRoute, notFound } from '@tanstack/react-router'
import { SYSTEM_SECTIONS } from '@/config/support-sections'
import { SoporteSistema } from '@/features/soporte-sistema'

// Una sección que no existe da la pantalla 404 en vez de una pantalla vacía.
export const Route = createFileRoute('/_app/soporte/sistema/$seccion/')({
  beforeLoad: ({ params }) => {
    if (!SYSTEM_SECTIONS.some((s) => s.id === params.seccion)) throw notFound()
  },
  component: Pantalla,
})

function Pantalla() {
  const { seccion } = Route.useParams()
  return <SoporteSistema seccion={seccion} />
}
