// Estado "captura cargada": resultado de /api/analyze, /api/demo o la captura en vivo.
// Todas las queries de captura incluyen `generation` en su clave: al cargar o cerrar una
// captura cambia y los datos viejos dejan de usarse (reemplaza version/refreshKey del front viejo).
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import { api } from '@/lib/api/client'
import { type Capture } from '@/lib/api/schemas'

type CaptureState = { capture: Capture | null; generation: number }

type CaptureContextValue = {
  /** Resumen de la captura cargada, o null si no hay ninguna. */
  capture: Capture | null
  hasCapture: boolean
  /** Cambia con cada captura nueva o cerrada: va en las claves de las queries. */
  generation: number
  /** true mientras se consulta si el backend ya tenía una captura (al abrir/recargar). */
  hydrating: boolean
  setCapture: (capture: Capture) => void
  clearCapture: () => void
}

const CaptureContext = createContext<CaptureContextValue | null>(null)

type CaptureProviderProps = {
  children: React.ReactNode
  /** Captura inicial (pruebas). Si se pasa, no se consulta al backend. */
  initialCapture?: Capture | null
  /** Consultar /api/capture al montar (por defecto sí, salvo con `initialCapture`). */
  hydrate?: boolean
}

export function CaptureProvider({
  children,
  initialCapture,
  hydrate,
}: CaptureProviderProps) {
  const shouldHydrate = hydrate ?? initialCapture === undefined
  const [state, setState] = useState<CaptureState>({
    capture: initialCapture ?? null,
    generation: initialCapture ? 1 : 0,
  })
  const [hydrating, setHydrating] = useState(shouldHydrate)

  const setCapture = useCallback((capture: Capture) => {
    setState((s) => ({ capture, generation: s.generation + 1 }))
  }, [])
  const clearCapture = useCallback(() => {
    setState((s) => ({ capture: null, generation: s.generation + 1 }))
  }, [])

  useEffect(() => {
    if (!shouldHydrate) return
    const ctl = new AbortController()
    api
      .capture(ctl.signal)
      .then((capture) => setCapture(capture))
      .catch(() => {
        /* 409 = no hay captura (lo normal); otro fallo lo avisan las demás queries */
      })
      .finally(() => {
        if (!ctl.signal.aborted) setHydrating(false)
      })
    return () => ctl.abort()
  }, [shouldHydrate, setCapture])

  const value = useMemo<CaptureContextValue>(
    () => ({
      capture: state.capture,
      hasCapture: state.capture !== null,
      generation: state.generation,
      hydrating,
      setCapture,
      clearCapture,
    }),
    [state, hydrating, setCapture, clearCapture]
  )

  return <CaptureContext value={value}>{children}</CaptureContext>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useCapture(): CaptureContextValue {
  const ctx = useContext(CaptureContext)
  if (!ctx) throw new Error('useCapture debe usarse dentro de CaptureProvider')
  return ctx
}
