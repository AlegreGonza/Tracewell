import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { HELP } from '@/lib/help'
import { Glossary } from './glossary'
import { HelpTip } from './help-tip'

describe('HelpTip', () => {
  it('un tema desconocido (o heredado de Object.prototype) no renderiza nada', () => {
    for (const topic of ['no-existe', '', 'constructor', 'toString']) {
      const { container, unmount } = render(<HelpTip topic={topic} />)
      expect(container).toBeEmptyDOMElement()
      unmount()
    }
  })

  it('botón con nombre «Ayuda: <título>», cerrado al inicio', () => {
    render(<HelpTip topic='resumen' />)
    const b = screen.getByRole('button', {
      name: `Ayuda: ${HELP.resumen.title}`,
    })
    expect(b).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('note')).toBeNull()
  })

  it('un clic muestra el texto didáctico y Escape lo cierra', async () => {
    const user = userEvent.setup()
    render(<HelpTip topic='resumen' />)
    await user.click(screen.getByRole('button'))
    expect(await screen.findByRole('note')).toHaveTextContent(HELP.resumen.text)
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('note')).toBeNull()
  })

  it('se opera con el teclado', async () => {
    const user = userEvent.setup()
    render(<HelpTip topic='tiempo' />)
    await user.tab()
    expect(screen.getByRole('button')).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('note')).toBeInTheDocument()
  })
})

describe('Glossary', () => {
  it('cerrado no muestra nada; abierto lista términos y filtra', async () => {
    const user = userEvent.setup()
    const { rerender } = render(
      <Glossary open={false} onOpenChange={() => {}} />
    )
    expect(screen.queryByRole('dialog')).toBeNull()
    rerender(<Glossary open onOpenChange={() => {}} />)
    expect(
      await screen.findByRole('dialog', { name: 'Glosario' })
    ).toBeInTheDocument()
    expect(screen.getByText('Paquete')).toBeInTheDocument()
    const box = screen.getByRole('searchbox', {
      name: 'Buscar en el glosario',
    })
    await user.type(box, 'nxdomain')
    expect(screen.getByText('NXDOMAIN')).toBeInTheDocument()
    expect(screen.queryByText('Paquete')).toBeNull()
    await user.clear(box)
    await user.type(box, 'zzzz')
    expect(screen.getByText('Ningún término coincide.')).toBeInTheDocument()
  })
})
