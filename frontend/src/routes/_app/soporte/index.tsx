import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/soporte/')({
  beforeLoad: () => {
    throw redirect({ to: '/soporte/sistema', replace: true })
  },
})
