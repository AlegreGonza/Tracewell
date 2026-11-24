// Preparación común de las pruebas (vitest + jsdom): matchers de jest-dom, MSW y limpieza.
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterAll, afterEach, beforeAll, vi } from 'vitest'
import { setToken } from '@/lib/api/token'
import { resetMockState } from './handlers'
import { server } from './server'

// jsdom no trae matchMedia, ResizeObserver ni scrollIntoView (los usan sidebar, cmdk y radix)
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList
}
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??=
  ResizeObserverStub as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
window.scrollTo = () => {} // lo llama el router al cambiar de pantalla
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

// Un pedido sin handler MSW falla la prueba en vez de salir a la red
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }))
afterEach(() => {
  cleanup()
  server.resetHandlers()
  resetMockState()
  setToken(null)
  window.sessionStorage.clear()
  vi.restoreAllMocks()
  vi.useRealTimers()
})
afterAll(() => server.close())
