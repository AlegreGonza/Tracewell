import { useEffect, useRef } from 'react'

type Handlers = Record<string, (event: KeyboardEvent) => void>

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return (
    target.isContentEditable ||
    ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)
  )
}

/**
 * Atajos de teclado de una pantalla: useShortcuts({ '/': enfocarFiltro, Escape: cerrarPanel }).
 * Las teclas de un carácter (como "/") se ignoran mientras se escribe en un campo; Escape siempre
 * funciona. Con Ctrl/Alt/Meta apretados no se dispara (eso es de Ctrl+K y del navegador).
 */
export function useShortcuts(handlers: Handlers, enabled = true): void {
  const ref = useRef(handlers)
  useEffect(() => {
    ref.current = handlers
  })

  useEffect(() => {
    if (!enabled) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.altKey || event.metaKey) return
      const handler = ref.current[event.key]
      if (!handler) return
      if (event.key.length === 1 && isTyping(event.target)) return
      if (event.key === '/') event.preventDefault() // no escribir "/" en el campo que se enfoca
      handler(event)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [enabled])
}
