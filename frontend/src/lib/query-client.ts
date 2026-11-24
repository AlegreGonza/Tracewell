// QueryClient único de la app: los errores de queries y mutations salen como toast.
import {
  MutationCache,
  QueryCache,
  QueryClient,
  type QueryClientConfig,
} from '@tanstack/react-query'
import { ApiError } from '@/lib/api/client'
import { notifyError } from '@/lib/api/errors'

/** Una query con `meta: { silent: true }` no muestra toast (el componente maneja su error). */
declare module '@tanstack/react-query' {
  interface Register {
    queryMeta: { silent?: boolean }
    mutationMeta: { silent?: boolean }
  }
}

// Los errores 4xx (token, validación, sin captura) no mejoran al reintentar.
function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
    return false
  }
  return failureCount < 1
}

export function createQueryClient(config: QueryClientConfig = {}): QueryClient {
  return new QueryClient({
    ...config,
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        refetchOnWindowFocus: false, // app de escritorio: los datos no cambian solos
        staleTime: 30_000,
        ...config.defaultOptions?.queries,
      },
      mutations: { retry: false, ...config.defaultOptions?.mutations },
    },
    queryCache: new QueryCache({
      onError: (error, query) => {
        if (!query.meta?.silent) notifyError(error)
      },
    }),
    mutationCache: new MutationCache({
      onError: (error, _vars, _ctx, mutation) => {
        if (!mutation.meta?.silent) notifyError(error)
      },
    }),
  })
}
