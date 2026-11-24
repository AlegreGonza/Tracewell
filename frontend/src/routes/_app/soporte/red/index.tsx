import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/soporte/red/')({
  beforeLoad: () => {
    throw redirect({
      to: '/soporte/red/$seccion',
      params: { seccion: 'config' },
      replace: true,
    })
  },
})
