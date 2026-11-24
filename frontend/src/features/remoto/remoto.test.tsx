import { renderRoute } from '@/test/render'
import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

describe('Acceso remoto', () => {
  it('agrupa las sesiones por servicio', async () => {
    await renderRoute('/capturas/remoto', { capture: true })
    expect(await screen.findByRole('heading', { name: /SSH/ })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /Telnet/ })).toBeInTheDocument()
    expect(screen.getAllByText('192.168.1.66').length).toBeGreaterThan(0)
  })
})
