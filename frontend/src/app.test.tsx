import { renderRoute } from '@/test/render'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

// La app real con todas las rutas, router en memoria y backend simulado (MSW).
const PANTALLAS = [
  ['/capturas/panorama', 'Panorama'],
  ['/capturas/alertas', 'Alertas y ATT&CK'],
  ['/capturas/equipos', 'Equipos'],
  ['/capturas/trafico', 'DNS y HTTP'],
  ['/capturas/remoto', 'Acceso remoto'],
  ['/capturas/cronologia', 'Cronología del caso'],
  ['/capturas/sesiones', 'Sesiones'],
  ['/capturas/indicadores', 'Indicadores (IOC)'],
  ['/capturas/reglas', 'Reglas'],
] as const

describe('rutas de captura', () => {
  it.each(PANTALLAS)(
    '%s muestra su pantalla con captura cargada',
    async (path, title) => {
      await renderRoute(path, { capture: true })
      expect(
        await screen.findByRole('heading', { level: 1, name: title })
      ).toBeInTheDocument()
    }
  )

  // Indicadores y Reglas se usan sin captura.
  it.each(PANTALLAS.filter(([p]) => !/indicadores|reglas/.test(p)))(
    '%s invita a abrir una captura si no hay ninguna',
    async (path) => {
      await renderRoute(path)
      expect(await screen.findByTestId('empty-capture')).toHaveTextContent(
        'Sin captura cargada'
      )
    }
  )

  it('/capturas redirige a las alertas', async () => {
    const { router } = await renderRoute('/capturas', { capture: true })
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/capturas/alertas')
    )
  })
})

describe('rutas de soporte', () => {
  it.each([
    ['/soporte/sistema/resumen', 'Sistema · Resumen'],
    ['/soporte/sistema/inicio', 'Sistema · Programas de inicio'],
    ['/soporte/red/config', 'Red · Configuración'],
    ['/soporte/red/monitoreo', 'Red · Monitoreo de cortes'],
  ])('%s no necesita captura', async (path, title) => {
    await renderRoute(path)
    expect(
      await screen.findByRole('heading', { level: 1, name: title })
    ).toBeInTheDocument()
  })

  it('/soporte lleva a la primera sección de Sistema', async () => {
    const { router } = await renderRoute('/soporte')
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/soporte/sistema/resumen')
    )
  })

  it('/soporte/red lleva a la configuración de red', async () => {
    const { router } = await renderRoute('/soporte/red')
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/soporte/red/config')
    )
  })

  it('una sección que no existe da la pantalla 404', async () => {
    await renderRoute('/soporte/sistema/inventada')
    expect(await screen.findByText('404')).toBeInTheDocument()
  })
})

describe('filtros en la URL', () => {
  it('sesiones valida y normaliza los filtros', async () => {
    const { router } = await renderRoute(
      '/capturas/sesiones?protocol=TCP&port=443&page=abc',
      { capture: true }
    )
    await screen.findByRole('heading', { level: 1, name: 'Sesiones' })
    expect(router.state.location.search).toEqual({
      protocol: 'TCP',
      port: 443,
      page: 1,
      size: 50,
    })
  })

  it('alertas conserva la severidad y descarta una inválida', async () => {
    const { router } = await renderRoute(
      '/capturas/alertas?severity=high&tactic=Discovery',
      { capture: true }
    )
    await screen.findByRole('heading', { level: 1, name: 'Alertas y ATT&CK' })
    expect(router.state.location.search).toEqual({
      severity: 'high',
      tactic: 'Discovery',
    })
  })
})

describe('marco de la aplicación', () => {
  it('muestra la marca, las secciones y "sin captura" en la barra lateral', async () => {
    await renderRoute('/')
    const nav = (await screen.findAllByText('Tracewell'))[0]
    expect(nav).toBeInTheDocument()
    for (const label of [
      'Panorama',
      'Alertas y ATT&CK',
      'Equipos',
      'DNS y HTTP',
      'Acceso remoto',
      'Cronología del caso',
      'Sesiones',
      'Indicadores (IOC)',
      'Reglas',
    ]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0)
    }
    expect(screen.getByText('Sin captura cargada')).toBeInTheDocument()
  })

  it('con captura la barra lateral muestra el archivo, sus números y el botón de cerrar', async () => {
    await renderRoute('/', { capture: true })
    expect(await screen.findByText('demo.pcap')).toBeInTheDocument()
    expect(
      screen.getByText(/45 paquetes · 32 sesiones · 3 alertas/)
    ).toBeInTheDocument()
  })

  it('cerrar la captura pide confirmación y vuelve al inicio sin captura', async () => {
    const user = userEvent.setup()
    const { router } = await renderRoute('/capturas/alertas', {
      capture: true,
    })
    await user.click(
      await screen.findByRole('button', { name: 'Cerrar captura' })
    )
    const dialog = await screen.findByRole('alertdialog')
    await user.click(
      within(dialog).getByRole('button', { name: 'Cerrar captura' })
    )
    await waitFor(() => expect(router.state.location.pathname).toBe('/'))
    expect(await screen.findByText('Sin captura cargada')).toBeInTheDocument()
  })

  it('una ruta inexistente muestra el 404 genérico', async () => {
    await renderRoute('/no-existe')
    expect(await screen.findByText('404')).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Volver al inicio' })
    ).toBeInTheDocument()
  })
})

describe('Ctrl+K', () => {
  it('abre el menú de navegación y lleva a la sección elegida', async () => {
    const user = userEvent.setup()
    const { router } = await renderRoute('/', { capture: true })
    await screen.findByRole('heading', { level: 1, name: 'Abrir captura' })
    await user.keyboard('{Control>}k{/Control}')
    const input = await screen.findByPlaceholderText(/Escribí una sección/)
    await user.type(input, 'Alertas')
    await user.keyboard('{Enter}')
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/capturas/alertas')
    )
  })
})
