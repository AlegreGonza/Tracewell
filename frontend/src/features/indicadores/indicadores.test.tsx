import { renderRoute } from '@/test/render'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => {
  delete window.pywebview
})

describe('Indicadores (IOC): elegir archivo', () => {
  it('sin ventana de escritorio no hay botón Examinar', async () => {
    await renderRoute('/capturas/indicadores')
    await screen.findByLabelText(/Ruta del archivo de indicadores/)
    expect(
      screen.queryByRole('button', { name: /Examinar/ })
    ).not.toBeInTheDocument()
  })

  it('en la ventana de escritorio, Examinar usa pick_file y carga esa lista', async () => {
    const pick = vi.fn(() => Promise.resolve('D:/listas/ioc.txt'))
    window.pywebview = { api: { pick_file: pick } }
    const user = userEvent.setup()
    await renderRoute('/capturas/indicadores')
    await user.click(await screen.findByRole('button', { name: /Examinar/ }))
    await waitFor(() => expect(pick).toHaveBeenCalledTimes(1))
  })
})
