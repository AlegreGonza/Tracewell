// Secciones de Soporte de red (las mismas que el frontend anterior: views/SupportView.jsx).
type SupportSection = { id: string; label: string }

export const SYSTEM_SECTIONS: SupportSection[] = [
  { id: 'resumen', label: 'Resumen' },
  { id: 'procesos', label: 'Procesos' },
  { id: 'puertos', label: 'Puertos abiertos' },
  { id: 'conexiones', label: 'Conexiones' },
  { id: 'servicios', label: 'Servicios' },
  { id: 'inicio', label: 'Programas de inicio' },
]

export const NETWORK_SECTIONS: SupportSection[] = [
  { id: 'config', label: 'Configuración' },
  { id: 'internet', label: '¿Hay Internet?' },
  { id: 'latencia', label: 'Latencia' },
  { id: 'dispositivos', label: 'Dispositivos' },
  { id: 'wifi', label: 'Wi-Fi' },
  { id: 'monitoreo', label: 'Monitoreo de cortes' },
  { id: 'herramientas', label: 'Herramientas' },
]

export const SYSTEM_NOTE =
  'Todo lo que se ve acá es de solo lectura: Tracewell mira tu equipo, no cambia ni termina nada. Algunos datos de procesos del sistema requieren abrirlo como administrador.'

export const NETWORK_NOTE =
  'Pruebas de solo lectura: miden y explican, nunca cambian la configuración. Las que salen a la red las pedís vos con un botón y cada una dice a quién se contacta.'
