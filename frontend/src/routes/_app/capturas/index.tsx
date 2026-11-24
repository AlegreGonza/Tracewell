import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/_app/capturas/')({
  beforeLoad: () => {
    throw redirect({ to: '/capturas/alertas', replace: true })
  },
})
