import { describe, expect, it } from 'vitest'
import { GLOSSARY, HELP } from './help'

describe('HELP', () => {
  it('cada tema tiene title y text no vacíos y ninguna clave wireshark', () => {
    expect(Object.keys(HELP).length).toBeGreaterThan(5)
    for (const [id, h] of Object.entries(HELP)) {
      expect(h.title.trim(), id).not.toBe('')
      expect(h.text.trim().length, id).toBeGreaterThan(20)
      expect('wireshark' in h, id).toBe(false)
    }
  })

  it('los ids son slugs simples y los títulos son únicos', () => {
    for (const id of Object.keys(HELP)) expect(id).toMatch(/^[a-z][a-z0-9_]*$/)
    const titles = Object.values(HELP).map((h) => h.title)
    expect(new Set(titles).size).toBe(titles.length)
  })

  it('ningún texto contiene marcado HTML', () => {
    for (const [id, h] of Object.entries(HELP)) {
      for (const v of [h.title, h.text])
        expect(v, id).not.toMatch(/<\/?[a-z][^>]*>/i)
    }
  })

  it('existen los temas de las pantallas de captura y de Soporte', () => {
    for (const id of [
      'resumen',
      'tiempo',
      'alertas',
      'attack',
      'riesgo',
      'sistema_resumen',
      'soporte_wifi',
    ]) {
      expect(HELP[id], id).toBeDefined()
    }
  })
})

describe('GLOSSARY', () => {
  it('son pares [término, texto] no vacíos con términos únicos', () => {
    expect(GLOSSARY.length).toBeGreaterThan(10)
    for (const entry of GLOSSARY) {
      expect(entry[0].trim()).not.toBe('')
      expect(entry[1].trim().length).toBeGreaterThan(10)
      expect(`${entry[0]} ${entry[1]}`).not.toMatch(/<\/?[a-z][^>]*>/i)
    }
    const terms = GLOSSARY.map(([t]) => t.toLowerCase())
    expect(new Set(terms).size).toBe(terms.length)
  })
})
