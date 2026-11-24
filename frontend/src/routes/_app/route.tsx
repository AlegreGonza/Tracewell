import { createFileRoute } from '@tanstack/react-router'
import { AppLayout } from '@/components/layout/app-layout'

// Todas las pantallas cuelgan de acá: barra lateral + Ctrl+K. No hay rutas protegidas (sin login).
export const Route = createFileRoute('/_app')({
  component: AppLayout,
})
