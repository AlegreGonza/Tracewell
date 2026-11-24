import { NETWORK_SECTIONS, SYSTEM_SECTIONS } from '@/config/support-sections'
import {
  Activity,
  AlertTriangle,
  Cable,
  History,
  LayoutDashboard,
  PlugZap,
  FolderOpen,
  ListTree,
  Monitor,
  Network,
  Ruler,
  ScanSearch,
} from 'lucide-react'
import { type SidebarData } from '../types'

// Orden y nombres de las secciones, como en la interfaz anterior (App.jsx).
export const sidebarData: SidebarData = {
  navGroups: [
    {
      title: 'Empezar',
      items: [{ title: 'Abrir captura', url: '/', icon: FolderOpen }],
    },
    {
      title: 'Captura',
      items: [
        { title: 'Panorama', url: '/capturas/panorama', icon: LayoutDashboard },
        {
          title: 'Alertas y ATT&CK',
          url: '/capturas/alertas',
          icon: AlertTriangle,
        },
        { title: 'Equipos', url: '/capturas/equipos', icon: Network },
        { title: 'DNS y HTTP', url: '/capturas/trafico', icon: Activity },
        { title: 'Acceso remoto', url: '/capturas/remoto', icon: PlugZap },
        {
          title: 'Cronología del caso',
          url: '/capturas/cronologia',
          icon: History,
        },
        { title: 'Sesiones', url: '/capturas/sesiones', icon: ListTree },
        {
          title: 'Indicadores (IOC)',
          url: '/capturas/indicadores',
          icon: ScanSearch,
        },
        { title: 'Reglas', url: '/capturas/reglas', icon: Ruler },
      ],
    },
    {
      title: 'Soporte de red',
      items: [
        {
          title: 'Sistema',
          icon: Monitor,
          items: SYSTEM_SECTIONS.map((s) => ({
            title: s.label,
            url: `/soporte/sistema/${s.id}`,
          })),
        },
        {
          title: 'Red',
          icon: Cable,
          items: NETWORK_SECTIONS.map((s) => ({
            title: s.label,
            url: `/soporte/red/${s.id}`,
          })),
        },
      ],
    },
  ],
}
