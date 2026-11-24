// Helpers de render para las pruebas de pantallas.
//
//   renderRoute('/capturas/alertas?severity=high', { capture: true })
//       → la app real (todas las rutas) con router en memoria, QueryClient de prueba y MSW.
//   renderWithProviders(<MiComponente />, { capture: true })
//       → un componente suelto con los mismos providers y un router mínimo (Link y useNavigate andan).
//
// `capture: true` simula una captura ya cargada (el backend simulado responde con los datos
// de ./fixtures); sin eso el backend simulado responde 409 "no hay una captura".
import { type ReactElement } from 'react'
import { QueryClientProvider, type QueryClient } from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
import { createAppRouter } from '@/router'
import { render, renderHook } from '@testing-library/react'
import { type Capture } from '@/lib/api/schemas'
import { createQueryClient } from '@/lib/query-client'
import { CaptureProvider } from '@/context/capture-provider'
import { DirectionProvider } from '@/context/direction-provider'
import { ThemeProvider } from '@/context/theme-provider'
import { Toaster } from '@/components/ui/sonner'
import { fixtures } from './fixtures'
import { mockState } from './handlers'

export type RenderOptions = {
  /** true = captura de demo ya cargada; o pasá otra captura. Por defecto, sin captura. */
  capture?: boolean | Capture
  /** QueryClient propio (por defecto uno de prueba sin reintentos). */
  queryClient?: QueryClient
}

/** QueryClient de prueba: sin reintentos y con los mismos avisos de error que la app. */
export function createTestQueryClient() {
  return createQueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0, gcTime: Infinity },
    },
  })
}

function setupCapture(capture: RenderOptions['capture']) {
  if (!capture) return { initial: null }
  mockState.loaded = true
  return { initial: capture === true ? (fixtures.capture as Capture) : capture }
}

function Providers({
  queryClient,
  initial,
  children,
}: {
  queryClient: QueryClient
  initial: Capture | null
  children: React.ReactNode
}) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <DirectionProvider>
          <CaptureProvider initialCapture={initial}>
            {children}
            <Toaster />
          </CaptureProvider>
        </DirectionProvider>
      </ThemeProvider>
    </QueryClientProvider>
  )
}

/** La aplicación completa, abierta en `path`, con router en memoria. */
export async function renderRoute(path: string, options: RenderOptions = {}) {
  const queryClient = options.queryClient ?? createTestQueryClient()
  const { initial } = setupCapture(options.capture)
  const history = createMemoryHistory({ initialEntries: [path] })
  const router = createAppRouter(queryClient, history)
  await router.load()
  const result = render(
    <Providers queryClient={queryClient} initial={initial}>
      <RouterProvider router={router} />
    </Providers>
  )
  return { ...result, router, queryClient }
}

/** Un componente suelto dentro de los providers y de un router mínimo. */
export async function renderWithProviders(
  ui: ReactElement,
  options: RenderOptions = {}
) {
  const queryClient = options.queryClient ?? createTestQueryClient()
  const { initial } = setupCapture(options.capture)
  const rootRoute = createRootRoute({ component: () => ui })
  const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: '/' })
  const router = createRouter({
    routeTree: rootRoute.addChildren([indexRoute]),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  })
  await router.load()
  const result = render(
    <Providers queryClient={queryClient} initial={initial}>
      <RouterProvider router={router} />
    </Providers>
  )
  return { ...result, router, queryClient }
}

/** Un hook (queries, mutations, contexto de captura) dentro de los mismos providers. */
export function renderHookWithProviders<T>(
  hook: () => T,
  options: RenderOptions = {}
) {
  const queryClient = options.queryClient ?? createTestQueryClient()
  const { initial } = setupCapture(options.capture)
  const result = renderHook(hook, {
    wrapper: ({ children }) => (
      <Providers queryClient={queryClient} initial={initial}>
        {children}
      </Providers>
    ),
  })
  return { ...result, queryClient }
}
