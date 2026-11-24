import { type ReactNode } from 'react'
import { NETWORK_NOTE, NETWORK_SECTIONS } from '@/config/support-sections'
import { Page } from '@/components/page'
import { Config } from './config'
import { Dispositivos } from './dispositivos'
import { Herramientas } from './herramientas'
import { Internet, Latencia } from './internet'
import { Monitoreo } from './monitoreo'
import { Wifi } from './wifi'

const SECCIONES: Record<string, () => ReactNode> = {
  config: Config,
  internet: Internet,
  latencia: Latencia,
  dispositivos: Dispositivos,
  wifi: Wifi,
  monitoreo: Monitoreo,
  herramientas: Herramientas,
}

/** Soporte de red, solo lectura: `seccion` ya viene validada contra NETWORK_SECTIONS. */
export function SoporteRed({ seccion }: { seccion: string }) {
  const label = NETWORK_SECTIONS.find((s) => s.id === seccion)?.label ?? seccion
  const Contenido = SECCIONES[seccion] ?? Config
  return (
    <Page title={`Red · ${label}`} description={NETWORK_NOTE}>
      <Contenido />
    </Page>
  )
}
