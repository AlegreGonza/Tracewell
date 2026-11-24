// Preferencias de la interfaz (tema, barra lateral) en cookies de la propia página.
const DEFAULT_MAX_AGE = 60 * 60 * 24 * 7 // 7 días

export function getCookie(name: string): string | undefined {
  if (typeof document === 'undefined') return undefined
  const prefix = `${name}=`
  const found = document.cookie.split('; ').find((c) => c.startsWith(prefix))
  return found ? decodeURIComponent(found.slice(prefix.length)) : undefined
}

export function setCookie(
  name: string,
  value: string,
  maxAge: number = DEFAULT_MAX_AGE
): void {
  if (typeof document === 'undefined') return
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=${maxAge}; SameSite=Lax`
}

export function removeCookie(name: string): void {
  if (typeof document === 'undefined') return
  document.cookie = `${name}=; path=/; max-age=0`
}
