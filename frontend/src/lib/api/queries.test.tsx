import { apiError } from '@/test/handlers'
import { renderHookWithProviders } from '@/test/render'
import { server } from '@/test/server'
import { waitFor } from '@testing-library/react'
import { http } from 'msw'
import { describe, expect, it } from 'vitest'
import {
  useAlerts,
  useExplain,
  useHosts,
  useLiveStatus,
  useRules,
  useSessions,
  useSystemOverview,
  useWiresharkFilter,
} from './queries'

describe('queries de captura', () => {
  it('sin captura cargada no piden nada', async () => {
    const { result } = renderHookWithProviders(() => useSessions())
    // deshabilitada: ni carga ni error (la pantalla muestra "sin captura")
    expect(result.current.fetchStatus).toBe('idle')
    expect(result.current.data).toBeUndefined()
  })

  it('con captura traen y validan las sesiones', async () => {
    const { result } = renderHookWithProviders(
      () => useSessions({ protocol: 'TCP' }),
      {
        capture: true,
      }
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.total).toBe(32)
    expect(result.current.data?.items[0].id).toBe(0)
  })

  it('mandan los filtros en la URL', async () => {
    let url = ''
    server.use(
      http.get('/api/sessions', ({ request }) => {
        url = request.url
        return Response.json({ total: 0, items: [] })
      })
    )
    const { result } = renderHookWithProviders(
      () => useSessions({ protocol: 'UDP', port: 53, ip: '' }),
      { capture: true }
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(new URL(url).search).toBe('?protocol=UDP&port=53')
  })

  it('alertas con severidad y con los campos MITRE', async () => {
    const { result } = renderHookWithProviders(() => useAlerts('high'), {
      capture: true,
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.[1]).toMatchObject({
      rule_id: 'port_scan',
      mitre_tactic: 'Discovery',
    })
  })

  it('hosts', async () => {
    const { result } = renderHookWithProviders(() => useHosts(), {
      capture: true,
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.total).toBe(6)
  })

  it('detalle de sesión: sin id no corre; con id sí', async () => {
    const none = renderHookWithProviders(() => useExplain(null), {
      capture: true,
    })
    expect(none.result.current.fetchStatus).toBe('idle')
    const withId = renderHookWithProviders(() => useExplain(5), {
      capture: true,
    })
    await waitFor(() => expect(withId.result.current.isSuccess).toBe(true))
    expect(withId.result.current.data?.outcome).toBe('abierta')
  })

  it('el filtro de Wireshark no corre con la IP vacía', async () => {
    const empty = renderHookWithProviders(() => useWiresharkFilter(''), {
      capture: true,
    })
    expect(empty.result.current.fetchStatus).toBe('idle')
    const ip = renderHookWithProviders(() => useWiresharkFilter('1.2.3.4'), {
      capture: true,
    })
    await waitFor(() => expect(ip.result.current.isSuccess).toBe(true))
    expect(ip.result.current.data?.wireshark_filter).toBe('ip.addr==1.2.3.4')
  })

  it('un 409 llega como error tipado a la query', async () => {
    // El backend dice "sin captura" aunque el contexto crea que hay una
    server.use(
      http.get('/api/alerts', () =>
        apiError(409, 'no hay una captura analizada')
      )
    )
    const { result } = renderHookWithProviders(() => useAlerts(), {
      capture: true,
    })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error).toMatchObject({ status: 409 })
  })

  it('una respuesta que no calza deja la query en error (no en blanco)', async () => {
    server.use(http.get('/api/sessions', () => Response.json({ total: 'x' })))
    const { result } = renderHookWithProviders(() => useSessions(), {
      capture: true,
    })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toMatch(/forma esperada/)
  })
})

describe('queries que no dependen de la captura', () => {
  it('reglas', async () => {
    const { result } = renderHookWithProviders(() => useRules())
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.items.length).toBeGreaterThan(5)
  })

  it('resumen del sistema', async () => {
    const { result } = renderHookWithProviders(() => useSystemOverview())
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.cpu_count).toBe(8)
  })

  it('estado de la captura en vivo', async () => {
    const { result } = renderHookWithProviders(() => useLiveStatus())
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.state).toBe('idle')
  })
})
