// La sesión abierta por id: sirve aunque no esté en la página que se está viendo.
import { useQuery } from '@tanstack/react-query'
import { request, buildQuery } from '@/lib/api/client'
import { keys } from '@/lib/api/queries'
import { sessionsPageSchema } from '@/lib/api/schemas'
import { useCapture } from '@/context/capture-provider'

const STALE = 5 * 60_000

/** La sesión `id` sola (el id es su posición en la lista completa). */
export function useSessionById(id: number | undefined, enabled = true) {
  const { generation, hasCapture } = useCapture()
  return useQuery({
    queryKey: keys.session(generation, id ?? '', 'self'),
    queryFn: async ({ signal }) => {
      const page = await request(
        `/api/sessions${buildQuery({ limit: 1, offset: id })}`,
        { schema: sessionsPageSchema, signal }
      )
      return page.items.find((s) => s.id === id) ?? null
    },
    enabled: hasCapture && enabled && id !== undefined,
    staleTime: STALE,
  })
}
