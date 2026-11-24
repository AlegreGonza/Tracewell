// Router de la aplicación. Se crea DESPUÉS de leer el token (ver main.tsx) porque lee la URL.
import { type QueryClient } from '@tanstack/react-query'
import { createRouter, type RouterHistory } from '@tanstack/react-router'
import { routeTree } from './routeTree.gen'

export function createAppRouter(
  queryClient: QueryClient,
  history?: RouterHistory
) {
  return createRouter({
    routeTree,
    history,
    context: { queryClient },
    defaultPreload: 'intent',
    defaultPreloadStaleTime: 0,
  })
}

// Registro del tipo del router para enlaces y parámetros tipados
declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>
  }
}
