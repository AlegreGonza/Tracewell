import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// token.ts guarda el token en una variable del módulo: se reimporta limpio en cada prueba.
async function load() {
  vi.resetModules()
  return import('./token')
}

beforeEach(() => {
  window.sessionStorage.clear()
  window.history.replaceState(null, '', '/')
})

afterEach(() => {
  delete window.pywebview
  vi.useRealTimers()
})

describe('token de la API', () => {
  it('lo toma de #token= y lo saca de la barra de direcciones', async () => {
    window.history.replaceState(null, '', '/?x=1#token=abc%2B123')
    const { initToken, getToken } = await load()
    expect(await initToken()).toBe('abc+123')
    expect(getToken()).toBe('abc+123')
    expect(window.location.hash).toBe('')
    expect(window.location.search).toBe('?x=1')
  })

  it('conserva la ruta al limpiar el hash (el router sigue en la misma pantalla)', async () => {
    window.history.replaceState(
      null,
      '',
      '/capturas/alertas?severity=high#token=t0k3n'
    )
    const { initToken } = await load()
    await initToken()
    expect(window.location.pathname).toBe('/capturas/alertas')
    expect(window.location.search).toBe('?severity=high')
    expect(window.location.hash).toBe('')
  })

  it('lo recuerda en sessionStorage al recargar', async () => {
    window.sessionStorage.setItem('tracewell-token', 'guardado')
    const { initToken } = await load()
    expect(await initToken()).toBe('guardado')
  })

  it('lo pide a la ventana de escritorio (pywebview.api.get_token)', async () => {
    window.pywebview = {
      api: { get_token: () => Promise.resolve('de-la-ventana') },
    }
    const { initToken } = await load()
    expect(await initToken()).toBe('de-la-ventana')
    expect(window.sessionStorage.getItem('tracewell-token')).toBe(
      'de-la-ventana'
    )
  })

  it('espera el evento pywebviewready si la API todavía no existe', async () => {
    const { initToken } = await load()
    const pending = initToken()
    window.pywebview = { api: { get_token: () => Promise.resolve('tarde') } }
    window.dispatchEvent(new Event('pywebviewready'))
    expect(await pending).toBe('tarde')
  })

  it('si get_token falla sigue sin token (no se cuelga)', async () => {
    window.pywebview = {
      api: { get_token: () => Promise.reject(new Error('x')) },
    }
    const { initToken } = await load()
    expect(await initToken()).toBeNull()
  })

  it('sin token ni ventana sigue sin token tras la espera (no se cuelga)', async () => {
    vi.useFakeTimers()
    const { initToken, getToken } = await load()
    const pending = initToken()
    await vi.advanceTimersByTimeAsync(2500)
    expect(await pending).toBeNull()
    expect(getToken()).toBeNull()
  })
})
