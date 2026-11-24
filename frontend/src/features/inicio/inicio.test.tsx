import { apiError } from '@/test/handlers'
import { renderRoute } from '@/test/render'
import { server } from '@/test/server'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http } from 'msw'
import { toast } from 'sonner'
import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => {
  delete window.pywebview
})

describe('Inicio (abrir captura)', () => {
  it('la demo carga la captura y lleva a las alertas', async () => {
    const user = userEvent.setup()
    const { router } = await renderRoute('/')
    await user.click(await screen.findByRole('button', { name: /Modo demo/ }))
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/capturas/alertas')
    )
    expect(await screen.findByText('demo.pcap')).toBeInTheDocument()
  })

  it('analiza la ruta escrita', async () => {
    const user = userEvent.setup()
    const { router } = await renderRoute('/')
    const analyze = screen.getByRole('button', { name: 'Analizar' })
    expect(analyze).toBeDisabled()
    await user.type(
      await screen.findByLabelText(/Ruta del archivo/),
      'C:\\Users\\yo\\Descargas\\red.pcap'
    )
    await user.click(analyze)
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/capturas/alertas')
    )
    expect(await screen.findByText('red.pcap')).toBeInTheDocument()
  })

  it('el 403 de carpetas permitidas se muestra tal cual y no cambia de pantalla', async () => {
    const detail =
      'la ruta está fuera de las carpetas permitidas (Descargas, Documentos, Escritorio, samples)'
    server.use(http.post('/api/analyze', () => apiError(403, detail)))
    const spy = vi.spyOn(toast, 'error')
    const user = userEvent.setup()
    const { router } = await renderRoute('/')
    await user.type(
      await screen.findByLabelText(/Ruta del archivo/),
      'D:\\x.pcap'
    )
    await user.click(screen.getByRole('button', { name: 'Analizar' }))
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(detail, expect.anything())
    )
    expect(router.state.location.pathname).toBe('/')
  })

  it('en la ventana de escritorio, Examinar usa pywebview.api.pick_file y analiza', async () => {
    window.pywebview = {
      api: { pick_file: () => Promise.resolve('C:\\samples\\elegido.pcap') },
    }
    const user = userEvent.setup()
    const { router } = await renderRoute('/')
    await user.click(await screen.findByRole('button', { name: /Examinar/ }))
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/capturas/alertas')
    )
    expect(await screen.findByText('elegido.pcap')).toBeInTheDocument()
  })

  it('sin ventana de escritorio no hay botón Examinar', async () => {
    await renderRoute('/')
    await screen.findByLabelText(/Ruta del archivo/)
    expect(
      screen.queryByRole('button', { name: /Examinar/ })
    ).not.toBeInTheDocument()
  })

  it('lista las interfaces para la captura en vivo', async () => {
    await renderRoute('/')
    expect(await screen.findByText('Captura en vivo')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Empezar a capturar/ })
    ).toBeDisabled()
  })
})
