import { describe, expect, it } from 'vitest'
import { alertasSearchSchema } from './alertas/search'
import { sesionesSearchSchema } from './sesiones/search'

describe('validateSearch de Sesiones', () => {
  it('sin parámetros da los valores por defecto', () => {
    expect(sesionesSearchSchema.parse({})).toEqual({ page: 1, size: 50 })
  })

  it('acepta filtros válidos', () => {
    expect(
      sesionesSearchSchema.parse({
        protocol: 'TCP',
        ip: '10.0.0.1',
        port: 443,
        page: 3,
        size: 100,
        sesion: 7,
      })
    ).toEqual({
      protocol: 'TCP',
      ip: '10.0.0.1',
      port: 443,
      page: 3,
      size: 100,
      sesion: 7,
    })
  })

  it('un valor inválido en la URL se descarta, no rompe la pantalla', () => {
    const parsed = sesionesSearchSchema.parse({
      port: 99999,
      page: 'abc',
      size: 1,
      sesion: -4,
      protocol: { x: 1 },
    })
    expect(parsed).toEqual({ page: 1, size: 50 })
  })
})

describe('validateSearch de Alertas', () => {
  it('sin parámetros no filtra nada', () => {
    expect(alertasSearchSchema.parse({})).toEqual({})
  })

  it('acepta severidad, táctica y alerta', () => {
    expect(
      alertasSearchSchema.parse({
        severity: 'high',
        tactic: 'Discovery',
        alerta: 'port_scan',
      })
    ).toEqual({ severity: 'high', tactic: 'Discovery', alerta: 'port_scan' })
  })

  it('una severidad desconocida se ignora', () => {
    expect(
      alertasSearchSchema.parse({ severity: 'enorme', tactic: 5 })
    ).toEqual({})
  })
})
