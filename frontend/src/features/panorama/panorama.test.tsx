import { renderRoute } from '@/test/render'
import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { riskLevel, riskScore } from './risk'

describe('Panorama', () => {
  it('muestra resumen, riesgo, protocolos y actividad', async () => {
    await renderRoute('/capturas/panorama', { capture: true })
    expect(await screen.findByText('Puntaje de riesgo')).toBeInTheDocument()
    expect(await screen.findByText('Distribución por protocolo')).toBeInTheDocument()
    expect(await screen.findByText('TCP')).toBeInTheDocument()
    expect(await screen.findByText('Tráfico en el tiempo')).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Ver todas las alertas' })
    ).toBeInTheDocument()
  })

  it('con la demo muestra «Quién más habla» y el caso guiado', async () => {
    await renderRoute('/capturas/panorama', { capture: true })
    expect(await screen.findByText('Quién más habla')).toBeInTheDocument()
    expect(
      await screen.findByText('Caso guiado: investigá esta demo')
    ).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Filtrar por 192.168.1.66' })
    ).toBeInTheDocument()
  })

  it('el puntaje suma por severidad y tiene tope de 100', () => {
    const a = (severity: string) => ({ severity }) as never
    expect(riskScore([a('high'), a('medium')])).toBe(37)
    expect(riskScore(Array.from({ length: 5 }, () => a('critical')))).toBe(100)
    expect(riskLevel(0).text).toBe('Sin alertas')
  })
})
