// Hooks de useMutation: acciones que cambian algo y pruebas de red que se piden con un botón.
// - Cargar/cerrar una captura actualiza el contexto de captura (cambia `generation`).
// - El resto invalida lo afectado. Los errores salen como toast desde el MutationCache.
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useCapture } from '@/context/capture-provider'
import { api, type LiveStartBody, type NoteBody, type RuleBody } from './client'
import { captureKey, keys } from './queries'

/** Quita del caché todo lo de la captura anterior (la clave cambia con `generation`). */
function useDropCaptureData() {
  const qc = useQueryClient()
  return () => {
    qc.removeQueries({ queryKey: ['capture'] })
    qc.removeQueries({ queryKey: keys.live })
  }
}

/* ---------------------------- cargar / cerrar captura --------------------------- */

/** POST /api/analyze: analiza un archivo .pcap/.pcapng (la ruta debe estar en carpetas permitidas). */
export function useAnalyze() {
  const { setCapture } = useCapture()
  const drop = useDropCaptureData()
  return useMutation({
    mutationFn: (path: string) => api.analyze(path),
    onSuccess: (capture) => {
      drop()
      setCapture(capture)
    },
  })
}

/** POST /api/demo: carga la captura de demostración. */
export function useDemo() {
  const { setCapture } = useCapture()
  const drop = useDropCaptureData()
  return useMutation({
    mutationFn: () => api.demo(),
    onSuccess: (capture) => {
      drop()
      setCapture(capture)
    },
  })
}

/** DELETE /api/capture: cierra la captura cargada. */
export function useCloseCapture() {
  const { clearCapture } = useCapture()
  const drop = useDropCaptureData()
  return useMutation({
    mutationFn: () => api.closeCapture(),
    onSuccess: () => {
      drop()
      clearCapture()
    },
  })
}

/* ------------------------------- captura en vivo ------------------------------ */

/** POST /api/live/start: empieza a capturar en una interfaz. */
export function useLiveStart() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: LiveStartBody) => api.liveStart(body),
    onSuccess: (status) => qc.setQueryData(keys.live, status),
  })
}

/** POST /api/live/stop: detiene la captura y la deja cargada como captura actual. */
export function useLiveStop() {
  const { setCapture } = useCapture()
  const qc = useQueryClient()
  const drop = useDropCaptureData()
  return useMutation({
    mutationFn: () => api.liveStop(),
    onSuccess: (capture) => {
      drop()
      setCapture(capture)
      void qc.invalidateQueries({ queryKey: keys.live })
    },
  })
}

/* ------------------------------ triaje, reglas, IOC ----------------------------- */

/** PUT /api/sessions/{id}/note: nota y marca "revisada" de una sesión. */
export function useSaveNote() {
  const qc = useQueryClient()
  const { generation } = useCapture()
  return useMutation({
    mutationFn: ({ id, ...body }: NoteBody & { id: string | number }) =>
      api.saveNote(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: captureKey(generation) }),
  })
}

/** POST /api/rules/preview: prueba una regla contra la captura cargada (no guarda nada). */
export function usePreviewRule() {
  return useMutation({ mutationFn: (body: RuleBody) => api.previewRule(body) })
}

/** POST /api/rules: guarda una regla de usuario. */
export function useSaveRule() {
  const qc = useQueryClient()
  const { generation } = useCapture()
  return useMutation({
    mutationFn: (body: RuleBody) => api.saveRule(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: keys.rules })
      await qc.invalidateQueries({ queryKey: captureKey(generation) })
    },
  })
}

function useInvalidateIocs() {
  const qc = useQueryClient()
  const { generation } = useCapture()
  return async () => {
    await qc.invalidateQueries({ queryKey: keys.iocs })
    // Los IOC marcan equipos, alertas y sesiones de la captura cargada
    await qc.invalidateQueries({ queryKey: captureKey(generation) })
  }
}

/** POST /api/iocs: carga una lista de indicadores de compromiso desde un archivo. */
export function useLoadIocs() {
  const refresh = useInvalidateIocs()
  return useMutation({
    mutationFn: (path: string) => api.loadIocs(path),
    onSuccess: refresh,
  })
}

/** DELETE /api/iocs: descarta la lista de indicadores. */
export function useClearIocs() {
  const refresh = useInvalidateIocs()
  return useMutation({ mutationFn: () => api.clearIocs(), onSuccess: refresh })
}

/* --------------------------------- descargas ---------------------------------- */

/** POST /api/download-ticket: devuelve la URL con un ticket de un solo uso (para <a download>). */
export function useDownloadUrl() {
  return useMutation({ mutationFn: (url: string) => api.ticketUrl(url) })
}

/* --------------------------- soporte de red (pruebas) --------------------------- */
// Todas son de solo lectura sobre el equipo; las que salen a la red se piden con un botón.

export const useInternetCheck = () =>
  useMutation({ mutationFn: () => api.supportInternet() })
export const useLatencyTest = () =>
  useMutation({
    mutationFn: (p: { host?: string; port?: number; samples?: number } = {}) =>
      api.supportLatency(p),
  })
export const usePing = () =>
  useMutation({
    mutationFn: ({ host, count }: { host: string; count?: number }) =>
      api.supportPing(host, count),
  })
export const useTraceroute = () =>
  useMutation({ mutationFn: (host: string) => api.supportTraceroute(host) })
export const usePortScan = () =>
  useMutation({
    mutationFn: ({ host, ports }: { host: string; ports?: string }) =>
      api.supportPorts(host, ports),
  })
export const useRdpCheck = () =>
  useMutation({
    mutationFn: ({ host, port }: { host: string; port?: number }) =>
      api.supportRdp(host, port),
  })
export const useTimeCheck = () =>
  useMutation({ mutationFn: (server?: string) => api.supportTime(server) })
export const useDevicesScan = () =>
  useMutation({
    mutationFn: (scan: boolean = false) => api.supportDevices(scan),
  })
export const useDuplicateIpCheck = () =>
  useMutation({ mutationFn: () => api.supportDuplicateIp() })

function useMonitorMutation<V>(
  fn: (v: V) => ReturnType<typeof api.monitorStop>
) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (status) => qc.setQueryData(keys.support('monitor'), status),
  })
}
/** Monitoreo de cortes: iniciar (intervalo en segundos), detener y borrar las muestras. */
export const useMonitorStart = () =>
  useMonitorMutation((interval?: number) => api.monitorStart(interval))
export const useMonitorStop = () => useMonitorMutation(() => api.monitorStop())
export const useMonitorClear = () =>
  useMonitorMutation(() => api.monitorClear())
