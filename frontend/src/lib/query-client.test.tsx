import { useQuery } from '@tanstack/react-query'
import { apiError } from '@/test/handlers'
import { createTestQueryClient, renderHookWithProviders } from '@/test/render'
import { server } from '@/test/server'
import { waitFor } from '@testing-library/react'
import { http } from 'msw'
import { toast } from 'sonner'
import { describe, expect, it, vi } from 'vitest'
import { api } from './api/client'
import { errorMessage, isAbort, notifyError } from './api/errors'
import { createQueryClient } from './query-client'

describe('errores globales -> toast', () => {
  it('un error de query muestra el detalle del backend en un toast', async () => {
    server.use(http.get('/api/rules', () => apiError(500, 'se rompió algo')))
    const spy = vi.spyOn(toast, 'error')
    const { result } = renderHookWithProviders(() =>
      useQuery({ queryKey: ['x'], queryFn: () => api.rules() })
    )
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(spy).toHaveBeenCalledWith('se rompió algo', expect.anything())
  })

  it('una respuesta que no calza avisa con un mensaje claro', async () => {
    server.use(http.get('/api/rules', () => Response.json({ items: 'no' })))
    const spy = vi.spyOn(toast, 'error')
    const { result } = renderHookWithProviders(() =>
      useQuery({ queryKey: ['x'], queryFn: () => api.rules() })
    )
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(spy.mock.calls[0][0]).toMatch(/no tiene la forma esperada/)
  })

  it('meta.silent evita el toast (la pantalla muestra su propio error)', async () => {
    server.use(http.get('/api/rules', () => apiError(500, 'callado')))
    const spy = vi.spyOn(toast, 'error')
    const { result } = renderHookWithProviders(() =>
      useQuery({
        queryKey: ['x'],
        queryFn: () => api.rules(),
        meta: { silent: true },
      })
    )
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(spy).not.toHaveBeenCalled()
  })

  it('el mismo error repetido reutiliza el id del toast (no se apila)', () => {
    const spy = vi.spyOn(toast, 'error')
    notifyError(new Error('igual'))
    notifyError(new Error('igual'))
    const ids = spy.mock.calls.map((c) => (c[1] as { id: string }).id)
    expect(new Set(ids).size).toBe(1)
  })

  it('un aborto no es un error para el usuario', () => {
    const spy = vi.spyOn(toast, 'error')
    notifyError(new DOMException('x', 'AbortError'))
    expect(spy).not.toHaveBeenCalled()
    expect(isAbort(new DOMException('x', 'AbortError'))).toBe(true)
  })

  it('errorMessage cubre errores sin texto', () => {
    expect(errorMessage(undefined)).toMatch(/inesperado/)
    expect(errorMessage(new Error('hola'))).toBe('hola')
  })
})

describe('reintentos', () => {
  it('no reintenta errores 4xx y reintenta una vez un fallo de red', async () => {
    const client = createQueryClient()
    const retry = client.getDefaultOptions().queries!.retry as (
      n: number,
      e: unknown
    ) => boolean
    const { ApiError } = await import('./api/client')
    expect(retry(0, new ApiError(403, 'x'))).toBe(false)
    expect(retry(0, new ApiError(0, 'sin red'))).toBe(true)
    expect(retry(1, new ApiError(0, 'sin red'))).toBe(false)
  })

  it('el cliente de prueba no reintenta nunca', () => {
    expect(createTestQueryClient().getDefaultOptions().queries!.retry).toBe(
      false
    )
  })
})
