import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/soporte/sistema/')({
  beforeLoad: () => {
    throw redirect({
      to: '/soporte/sistema/$seccion',
      params: { seccion: 'resumen' },
      replace: true,
    })
  },
})
