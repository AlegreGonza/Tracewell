import { apiError, mockState } from '@/test/handlers'
import { renderHookWithProviders } from '@/test/render'
import { server } from '@/test/server'
import { act, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { toast } from 'sonner'
import { describe, expect, it, vi } from 'vitest'
import { useCapture } from '@/context/capture-provider'
import {
  useAnalyze,
  useClearIocs,
  useCloseCapture,
  useDemo,
  useLiveStart,
  useLiveStop,
  useLoadIocs,
  useMonitorStart,
  useSaveNote,
  useSaveRule,
} from './mutations'
import { useSessions } from './queries'

describe('cargar y cerrar la captura', () => {
  it('analizar un archivo deja la captura cargada y cambia la generación', async () => {
    const { result } = renderHookWithProviders(() => ({
      cap: useCapture(),
      analyze: useAnalyze(),
    }))
    expect(result.current.cap.hasCapture).toBe(false)
    const before = result.current.cap.generation
    await act(() => result.current.analyze.mutateAsync('C:\\caps\\mi.pcap'))
    expect(result.current.cap.capture?.source).toBe('mi.pcap')
    expect(result.current.cap.generation).toBeGreaterThan(before)
  })

  it('la demo carga la captura de ejemplo', async () => {
    const { result } = renderHookWithProviders(() => ({
      cap: useCapture(),
      demo: useDemo(),
    }))
    await act(() => result.current.demo.mutateAsync())
    expect(result.current.cap.capture?.source).toBe('demo.pcap')
    expect(result.current.cap.capture?.stats.sessions).toBe(32)
  })

  it('cargar otra captura refresca las queries de captura (clave nueva)', async () => {
    const { result } = renderHookWithProviders(
      () => ({ sessions: useSessions(), demo: useDemo() }),
      { capture: true }
    )
    await waitFor(() => expect(result.current.sessions.isSuccess).toBe(true))
    let calls = 0
    server.use(
      http.get('/api/sessions', () => {
        calls += 1
        return HttpResponse.json({ total: 1, items: [] })
      })
    )
    await act(() => result.current.demo.mutateAsync())
    await waitFor(() => expect(result.current.sessions.data?.total).toBe(1))
    expect(calls).toBe(1)
  })

  it('cerrar la captura la descarta', async () => {
    const { result } = renderHookWithProviders(
      () => ({ cap: useCapture(), close: useCloseCapture() }),
      { capture: true }
    )
    expect(result.current.cap.hasCapture).toBe(true)
    await act(() => result.current.close.mutateAsync())
    expect(result.current.cap.hasCapture).toBe(false)
    expect(mockState.loaded).toBe(false)
  })

  it('un 403 de carpeta no permitida llega tal cual al toast', async () => {
    const detail =
      'la ruta está fuera de las carpetas permitidas (Descargas, Documentos)'
    server.use(http.post('/api/analyze', () => apiError(403, detail)))
    const spy = vi.spyOn(toast, 'error')
    const { result } = renderHookWithProviders(() => useAnalyze())
    await act(async () => {
      await result.current.mutateAsync('D:\\x.pcap').catch(() => undefined)
    })
    expect(spy).toHaveBeenCalledWith(detail, expect.anything())
  })
})

describe('captura en vivo', () => {
  it('start devuelve el estado y stop deja la captura cargada', async () => {
    const { result } = renderHookWithProviders(() => ({
      cap: useCapture(),
      start: useLiveStart(),
      stop: useLiveStop(),
    }))
    const status = await act(() =>
      result.current.start.mutateAsync({ interface: 'Ethernet' })
    )
    expect(status.state).toBe('running')
    await act(() => result.current.stop.mutateAsync())
    expect(result.current.cap.hasCapture).toBe(true)
  })
})

describe('triaje, reglas e IOC', () => {
  it('guardar una nota manda el cuerpo y vuelve a pedir las sesiones', async () => {
    let sessionCalls = 0
    server.use(
      http.get('/api/sessions', () => {
        sessionCalls += 1
        return HttpResponse.json({ total: 0, items: [] })
      })
    )
    const { result } = renderHookWithProviders(
      () => ({ sessions: useSessions(), note: useSaveNote() }),
      { capture: true }
    )
    await waitFor(() => expect(sessionCalls).toBe(1))
    await act(() =>
      result.current.note.mutateAsync({
        id: 5,
        note: 'revisar',
        reviewed: true,
      })
    )
    expect(mockState.notes.get('5')).toEqual({
      note: 'revisar',
      reviewed: true,
    })
    await waitFor(() => expect(sessionCalls).toBe(2))
  })

  it('guardar una regla', async () => {
    const { result } = renderHookWithProviders(() => useSaveRule(), {
      capture: true,
    })
    const saved = await act(() =>
      result.current.mutateAsync({ name: 'Mi regla', severity: 'low' })
    )
    expect(saved).toMatchObject({ id: 'regla-nueva' })
  })

  it('cargar y descartar la lista de IOC', async () => {
    const { result } = renderHookWithProviders(() => ({
      load: useLoadIocs(),
      clear: useClearIocs(),
    }))
    const loaded = await act(() =>
      result.current.load.mutateAsync('C:\\listas\\feed.txt')
    )
    expect(loaded.loaded).toBe(true)
    const cleared = await act(() => result.current.clear.mutateAsync())
    expect(cleared.loaded).toBe(false)
  })

  it('el monitoreo de cortes arranca y actualiza el estado en caché', async () => {
    const { result } = renderHookWithProviders(() => useMonitorStart())
    const status = await act(() => result.current.mutateAsync(5))
    expect(status.running).toBe(true)
  })
})
