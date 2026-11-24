import { renderRoute } from '@/test/render'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

describe('Tráfico (DNS y HTTP)', () => {
  it('lista los nombres DNS con sus pistas', async () => {
    await renderRoute('/capturas/trafico', { capture: true })
    expect(await screen.findByText('www.example.com')).toBeInTheDocument()
    expect(screen.getByText(/parece generado al azar/)).toBeInTheDocument()
  })

  it('la pestaña HTTP muestra el pedido y el archivo', async () => {
    const user = userEvent.setup()
    await renderRoute('/capturas/trafico', { capture: true })
    await user.click(await screen.findByRole('tab', { name: 'HTTP' }))
    expect(await screen.findByText(/Archivo index: Texto/)).toBeInTheDocument()
    expect(screen.getByText('GET')).toBeInTheDocument()
  })
})
