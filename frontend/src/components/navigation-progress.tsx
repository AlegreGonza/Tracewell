import { useEffect, useRef } from 'react'
import { useIsMutating } from '@tanstack/react-query'
import { useRouterState } from '@tanstack/react-router'
import LoadingBar, { type LoadingBarRef } from 'react-top-loading-bar'

/** Barra fina arriba: se mueve al cambiar de pantalla y mientras corre una mutation (analizar, guardar...). */
export function NavigationProgress() {
  const ref = useRef<LoadingBarRef>(null)
  const routing = useRouterState({ select: (s) => s.status === 'pending' })
  const mutating = useIsMutating() > 0
  const busy = routing || mutating

  useEffect(() => {
    if (busy) {
      ref.current?.continuousStart()
    } else {
      ref.current?.complete()
    }
  }, [busy])

  return (
    <LoadingBar color='var(--primary)' ref={ref} shadow={true} height={2} />
  )
}
