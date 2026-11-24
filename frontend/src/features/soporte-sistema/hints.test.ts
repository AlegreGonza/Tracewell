import { describe, expect, it } from 'vitest'
import { HINT_LABEL, hintLabel } from './hints'

describe('HINT_LABEL', () => {
  it('cubre los tres códigos de pista que manda el servidor', () => {
    expect(Object.keys(HINT_LABEL).sort()).toEqual(
      ['borrado', 'carpeta_temporal', 'nombre_de_windows'].sort()
    )
  })

  it('las etiquetas son textos cortos y planos', () => {
    for (const label of Object.values(HINT_LABEL)) {
      expect(label.length).toBeLessThan(50)
      expect(label).not.toMatch(/[<>]/)
    }
  })

  it('un código desconocido se muestra tal cual (también "constructor")', () => {
    expect(hintLabel('otra_cosa')).toBe('otra_cosa')
    expect(hintLabel('constructor')).toBe('constructor')
    expect(hintLabel('borrado')).toBe('Archivo borrado')
  })
})
