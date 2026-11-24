import { QueryClientProvider, type QueryClient } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { CaptureProvider } from '@/context/capture-provider'
import { DirectionProvider } from '@/context/direction-provider'
import { FontProvider } from '@/context/font-provider'
import { ThemeProvider } from '@/context/theme-provider'
import { type createAppRouter } from './router'

type AppProps = {
  queryClient: QueryClient
  router: ReturnType<typeof createAppRouter>
}

/** Todos los providers de la aplicación (los mismos que arma renderWithProviders en pruebas). */
export function App({ queryClient, router }: AppProps) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <FontProvider>
          <DirectionProvider>
            <CaptureProvider>
              <RouterProvider router={router} />
            </CaptureProvider>
          </DirectionProvider>
        </FontProvider>
      </ThemeProvider>
    </QueryClientProvider>
  )
}
