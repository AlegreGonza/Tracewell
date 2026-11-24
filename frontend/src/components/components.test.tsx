import { useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiError } from '@/test/handlers'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/server'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http } from 'msw'
import { describe, expect, it, vi } from 'vitest'
import { api } from '@/lib/api/client'
import { SEVERITY_LABEL } from '@/lib/severity'
import { useShortcuts } from '@/hooks/use-shortcuts'
import { ConfirmDialog } from './confirm-dialog'
import { QueryBoundary } from './query-boundary'
import { SeverityBadge } from './severity-badge'
import { CardSkeleton, TableSkeleton } from './skeletons'

describe('SeverityBadge', () => {
  it.each(Object.entries(SEVERITY_LABEL))(
    'severidad %s muestra "%s"',
    (severity, label) => {
      render(
        <SeverityBadge severity={severity as keyof typeof SEVERITY_LABEL} />
      )
      const badge = screen.getByText(label)
      expect(badge).toHaveAttribute('data-severity', severity)
      expect(badge.className).toContain(`text-sev-${severity}`)
    }
  )

  it('acepta un texto propio', () => {
    render(<SeverityBadge severity='high'>3 alertas</SeverityBadge>)
    expect(screen.getByText('3 alertas')).toBeInTheDocument()
  })
})

describe('skeletons', () => {
  it('TableSkeleton dibuja filas x columnas y avisa que está cargando', () => {
    render(<TableSkeleton rows={3} cols={4} />)
    const status = screen.getByRole('status', { name: 'Cargando datos' })
    expect(status.querySelectorAll('[data-slot=skeleton]')).toHaveLength(
      1 + 3 * 4
    )
  })

  it('CardSkeleton', () => {
    render(<CardSkeleton />)
    expect(
      screen.getByRole('status', { name: 'Cargando datos' })
    ).toBeInTheDocument()
  })
})

function ReglasBoundary() {
  const query = useQuery({
    queryKey: ['reglas'],
    queryFn: () => api.rules(),
    meta: { silent: true },
  })
  return (
    <QueryBoundary
      query={query}
      isEmpty={(d) => d.items.length === 0}
      empty={<p>Sin reglas</p>}
    >
      {(d) => <p>{d.items.length} reglas</p>}
    </QueryBoundary>
  )
}

describe('QueryBoundary', () => {
  it('esqueleto mientras carga y los datos al llegar', async () => {
    await renderWithProviders(<ReglasBoundary />)
    expect(
      screen.getByRole('status', { name: 'Cargando datos' })
    ).toBeInTheDocument()
    expect(await screen.findByText('9 reglas')).toBeInTheDocument()
  })

  it('error claro con Reintentar (no pantalla en blanco)', async () => {
    const user = userEvent.setup()
    server.use(
      http.get('/api/rules', () => apiError(500, 'falló el backend'), {
        once: true,
      })
    )
    await renderWithProviders(<ReglasBoundary />)
    expect(await screen.findByText('falló el backend')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /Reintentar/ }))
    expect(await screen.findByText('9 reglas')).toBeInTheDocument()
  })

  it('una respuesta con otra forma se explica en pantalla', async () => {
    server.use(http.get('/api/rules', () => Response.json({ items: 'no' })))
    await renderWithProviders(<ReglasBoundary />)
    expect(
      await screen.findByText(/no tiene la forma esperada/)
    ).toBeInTheDocument()
  })

  it('lista vacía muestra el estado vacío', async () => {
    server.use(http.get('/api/rules', () => Response.json({ items: [] })))
    await renderWithProviders(<ReglasBoundary />)
    expect(await screen.findByText('Sin reglas')).toBeInTheDocument()
  })
})

function Atajos({ onEscape }: { onEscape: () => void }) {
  const ref = useRef<HTMLInputElement>(null)
  useShortcuts({ '/': () => ref.current?.focus(), Escape: onEscape })
  return <input ref={ref} aria-label='filtro' />
}

describe('useShortcuts', () => {
  it('"/" enfoca el filtro sin escribir la barra', async () => {
    const user = userEvent.setup()
    render(<Atajos onEscape={() => {}} />)
    await user.keyboard('/')
    const input = screen.getByLabelText('filtro')
    expect(input).toHaveFocus()
    expect(input).toHaveValue('')
  })

  it('"/" escrito dentro de un campo se queda como texto', async () => {
    const user = userEvent.setup()
    render(<Atajos onEscape={() => {}} />)
    await user.click(screen.getByLabelText('filtro'))
    await user.keyboard('a/b')
    expect(screen.getByLabelText('filtro')).toHaveValue('a/b')
  })

  it('Escape funciona incluso escribiendo', async () => {
    const onEscape = vi.fn()
    const user = userEvent.setup()
    render(<Atajos onEscape={onEscape} />)
    await user.click(screen.getByLabelText('filtro'))
    await user.keyboard('{Escape}')
    expect(onEscape).toHaveBeenCalledOnce()
  })

  it('con Ctrl apretado no se dispara (es de Ctrl+K y del navegador)', async () => {
    const onEscape = vi.fn()
    const user = userEvent.setup()
    render(<Atajos onEscape={onEscape} />)
    await user.keyboard('{Control>}{Escape}{/Control}')
    expect(onEscape).not.toHaveBeenCalled()
  })
})

describe('ConfirmDialog', () => {
  it('muestra título y descripción y llama a handleConfirm', async () => {
    const handleConfirm = vi.fn()
    const user = userEvent.setup()
    render(
      <ConfirmDialog
        open
        onOpenChange={vi.fn()}
        title='Borrar regla'
        desc='No se puede deshacer.'
        confirmText='Borrar'
        handleConfirm={handleConfirm}
      />
    )
    expect(
      screen.getByRole('heading', { name: 'Borrar regla' })
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Borrar' }))
    await waitFor(() => expect(handleConfirm).toHaveBeenCalledOnce())
  })
})
