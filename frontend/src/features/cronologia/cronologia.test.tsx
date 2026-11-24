import { renderRoute } from '@/test/render'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

describe('Cronología del caso', () => {
  it('lista los hechos y permite limitar a un equipo', async () => {
    const user = userEvent.setup()
    await renderRoute('/capturas/cronologia', { capture: true })
    expect(
      await screen.findByText('Credenciales FTP en texto claro')
    ).toBeInTheDocument()
    await user.type(screen.getByLabelText('Equipo (IP)'), '192.168.1.66')
    await user.click(screen.getByRole('button', { name: 'Limitar al equipo' }))
    expect(
      await screen.findByRole('button', { name: 'Quitar filtro' })
    ).toBeInTheDocument()
  })
})
