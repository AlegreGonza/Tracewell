// Token de la API: lo genera main.py en cada arranque y lo entrega a la ventana o a la URL.
// IMPORTANTE: `initToken()` se espera en main.tsx ANTES de crear el router. Si el router
// arrancara primero, leería la URL con el `#token=...` y el token quedaría en el historial.
type PywebviewApi = Record<
  string,
  ((...args: unknown[]) => Promise<unknown>) | undefined
>

declare global {
  interface Window {
    pywebview?: { api?: PywebviewApi }
  }
}

const KEY = 'tracewell-token'
const WAIT_MS = 2000 // cuánto esperamos a la ventana de escritorio antes de seguir sin token

let token: string | null = null

export function getToken(): string | null {
  return token
}

function fromHash(): string | null {
  const m = /[#&]token=([^&]+)/.exec(window.location.hash)
  if (!m) return null
  // Se saca de la barra de direcciones: no queda en el historial ni se copia por error.
  window.history.replaceState(
    null,
    '',
    window.location.pathname + window.location.search
  )
  return decodeURIComponent(m[1])
}

function fromSession(): string | null {
  try {
    return window.sessionStorage.getItem(KEY)
  } catch {
    return null
  }
}

function remember(value: string): void {
  try {
    window.sessionStorage.setItem(KEY, value)
  } catch {
    /* sin sessionStorage: el token vive solo en memoria */
  }
}

function fromDesktop(): Promise<string | null> {
  return new Promise((resolve) => {
    const ask = () => {
      const getTokenFn = window.pywebview?.api?.get_token
      if (typeof getTokenFn !== 'function') return resolve(null)
      getTokenFn().then(
        (t) => resolve(typeof t === 'string' ? t : null),
        () => resolve(null)
      )
    }
    if (window.pywebview?.api) return ask()
    window.addEventListener('pywebviewready', ask, { once: true })
    setTimeout(() => resolve(null), WAIT_MS)
  })
}

/** Se llama una vez antes de dibujar la interfaz: #token= (navegador) o la ventana de escritorio. */
export async function initToken(): Promise<string | null> {
  token = fromHash() ?? fromSession() ?? (await fromDesktop())
  if (token) remember(token)
  return token
}

/** Solo para pruebas: fija o borra el token en memoria. */
export function setToken(value: string | null): void {
  token = value
}
