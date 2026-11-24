import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { renderRoute } from '@/test/render'

describe('Soporte · Sistema', () => {
  it('el resumen muestra los medidores sin necesitar captura', async () => {
    await renderRoute('/soporte/sistema/resumen')
    expect(await screen.findByText('Procesador')).toBeInTheDocument()
    expect(screen.getByText('Memoria')).toBeInTheDocument()
  })

  it('los procesos se listan como texto', async () => {
    await renderRoute('/soporte/sistema/procesos')
    expect(await screen.findByRole('table')).toBeInTheDocument()
  })
})
