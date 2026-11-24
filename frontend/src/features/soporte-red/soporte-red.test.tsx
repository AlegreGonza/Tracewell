import { renderRoute } from '@/test/render'
import { server } from '@/test/server'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'

describe('Soporte de red', () => {
  it('config: lee los adaptadores sin salir a la red', async () => {
    await renderRoute('/soporte/red/config')
    expect(
      await screen.findByText('192.168.1.10 / 255.255.255.0')
    ).toBeInTheDocument()
  })

  it('internet: la prueba corre solo al apretar el botón', async () => {
    const user = userEvent.setup()
    await renderRoute('/soporte/red/internet')
    const btn = await screen.findByRole('button', { name: 'Comprobar ahora' })
    expect(screen.queryByText(/Todo funciona/)).not.toBeInTheDocument()
    await user.click(btn)
    expect(await screen.findByText(/Todo funciona/)).toBeInTheDocument()
    expect(screen.getByText('Adaptador de red')).toBeInTheDocument()
  })

  it('herramientas: el ping muestra el resultado y exige un destino', async () => {
    const user = userEvent.setup()
    await renderRoute('/soporte/red/herramientas')
    const btn = await screen.findByRole('button', { name: 'Hacer ping (4)' })
    expect(btn).toBeDisabled()
    await user.type(
      screen.getByLabelText('Equipo o IP', { selector: '#ping-host' }),
      '127.0.0.1'
    )
    await user.click(btn)
    expect(await screen.findByText(/1 de 1 respuestas/)).toBeInTheDocument()
  })

  it('monitoreo: empezar manda el intervalo y refleja el estado', async () => {
    const user = userEvent.setup()
    let interval: string | null = null
    server.use(
      http.post('/api/support/monitor/start', ({ request }) => {
        interval = new URL(request.url).searchParams.get('interval')
        return HttpResponse.json({
          running: true,
          interval: 2,
          started_at: 1,
          total: 0,
          availability_pct: null,
          current: 'sin datos',
          latency: null,
          samples: [],
          outages: [],
          outage_count: 0,
          downtime_seconds: 0,
        })
      })
    )
    await renderRoute('/soporte/red/monitoreo')
    await user.click(
      await screen.findByRole('button', { name: 'Empezar a monitorear' })
    )
    expect(
      await screen.findByRole('button', { name: 'Detener' })
    ).toBeInTheDocument()
    await waitFor(() => expect(interval).toBe('2'))
  })
})
