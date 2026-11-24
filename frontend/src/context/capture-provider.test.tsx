import { fixtures } from '@/test/fixtures'
import { mockState } from '@/test/handlers'
import { renderHookWithProviders } from '@/test/render'
import { act, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { type Capture } from '@/lib/api/schemas'
import { useCapture } from './capture-provider'

describe('CaptureProvider', () => {
  it('sin captura en el backend arranca vacío', async () => {
    const { result } = renderHookWithProviders(() => useCapture())
    expect(result.current.hasCapture).toBe(false)
    expect(result.current.capture).toBeNull()
  })

  it('con captura inicial no consulta al backend', () => {
    const { result } = renderHookWithProviders(() => useCapture(), {
      capture: true,
    })
    expect(result.current.hasCapture).toBe(true)
    expect(result.current.hydrating).toBe(false)
    expect(result.current.capture?.source).toBe('demo.pcap')
  })

  it('setCapture y clearCapture cambian la generación (clave de las queries)', () => {
    const { result } = renderHookWithProviders(() => useCapture())
    const g0 = result.current.generation
    act(() => result.current.setCapture(fixtures.capture as Capture))
    const g1 = result.current.generation
    expect(result.current.hasCapture).toBe(true)
    expect(g1).toBeGreaterThan(g0)
    act(() => result.current.clearCapture())
    expect(result.current.hasCapture).toBe(false)
    expect(result.current.generation).toBeGreaterThan(g1)
  })

  it('fuera del provider da un error claro', async () => {
    const { renderHook } = await import('@testing-library/react')
    expect(() => renderHook(() => useCapture())).toThrow(/CaptureProvider/)
  })

  it('hidrata desde /api/capture cuando se monta sin captura inicial', async () => {
    mockState.loaded = true
    const { CaptureProvider } = await import('./capture-provider')
    const { renderHook } = await import('@testing-library/react')
    const { result } = renderHook(() => useCapture(), {
      wrapper: ({ children }) => <CaptureProvider>{children}</CaptureProvider>,
    })
    expect(result.current.hydrating).toBe(true)
    await waitFor(() => expect(result.current.hydrating).toBe(false))
    expect(result.current.capture?.source).toBe('demo.pcap')
  })
})
