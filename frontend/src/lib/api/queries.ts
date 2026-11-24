// Hooks de TanStack Query para cada endpoint de lectura.
// - Las de captura llevan `generation` (contexto de captura) en la clave y solo corren con una
//   captura cargada: al abrir otra, los datos viejos dejan de usarse solos.
// - Las de sistema/red no dependen de la captura.
// - Los errores salen como toast desde el QueryCache (lib/query-client.ts); pasá
//   `meta: { silent: true }` en las opciones si la pantalla muestra su propio error.
import { useQuery, type UseQueryOptions } from '@tanstack/react-query'
import { useCapture } from '@/context/capture-provider'
import { api, type SessionFilters } from './client'
import { type LiveStatus, type MonitorStatus } from './schemas'

type Extra<T = unknown> = {
  enabled?: boolean
  /** ms entre consultas, o una función de los datos actuales (p. ej. solo mientras corre). */
  refetchInterval?:
    | number
    | false
    | ((query: {
        state: { data: T | undefined }
      }) => number | false | undefined)
  staleTime?: number
}

const CAPTURE_STALE = 5 * 60_000 // la captura no cambia salvo con una mutation
const LIVE_STALE = 0 // sistema/red: se consulta de nuevo cada vez

/** Claves de las queries de captura (para invalidar desde mutations o pruebas). */
export const captureKey = (generation: number) =>
  ['capture', generation] as const
export const keys = {
  sessions: (g: number, f?: SessionFilters) =>
    [...captureKey(g), 'sessions', f ?? {}] as const,
  stats: (g: number, f?: SessionFilters) =>
    [...captureKey(g), 'stats', f ?? {}] as const,
  timeline: (g: number) => [...captureKey(g), 'timeline'] as const,
  alerts: (g: number, severity?: string) =>
    [...captureKey(g), 'alerts', severity ?? null] as const,
  hosts: (g: number, limit?: number) =>
    [...captureKey(g), 'hosts', limit ?? null] as const,
  hostsByMac: (g: number) => [...captureKey(g), 'hosts-by-mac'] as const,
  graph: (g: number, limit?: number) =>
    [...captureKey(g), 'graph', limit ?? null] as const,
  dns: (g: number, q?: string) => [...captureKey(g), 'dns', q ?? ''] as const,
  http: (g: number) => [...captureKey(g), 'http'] as const,
  caseTimeline: (g: number, host?: string) =>
    [...captureKey(g), 'case-timeline', host ?? ''] as const,
  remote: (g: number, service?: string) =>
    [...captureKey(g), 'remote', service ?? ''] as const,
  session: (g: number, id: string | number, part: string, extra?: unknown) =>
    [...captureKey(g), 'session', String(id), part, extra ?? null] as const,
  packet: (g: number, index: string | number) =>
    [...captureKey(g), 'packet', String(index)] as const,
  wiresharkFilter: (g: number, ip: string) =>
    [...captureKey(g), 'wireshark-filter', ip] as const,
  rules: ['rules'] as const,
  iocs: ['iocs'] as const,
  interfaces: ['interfaces'] as const,
  live: ['live-status'] as const,
  system: (part: string, extra?: unknown) =>
    ['system', part, extra ?? null] as const,
  support: (part: string) => ['support', part] as const,
}

/** Opciones comunes de las queries que dependen de la captura cargada. */
function useCaptureQuery<T>(
  queryKey: readonly unknown[],
  queryFn: (signal: AbortSignal) => Promise<T>,
  extra: Extra<T> & { gate?: boolean } = {}
) {
  const { hasCapture } = useCapture()
  const { gate = true, enabled = true, ...rest } = extra
  // La clave la arma cada hook con sus parámetros; queryFn recibe el cierre equivalente.
  // eslint-disable-next-line @tanstack/query/exhaustive-deps
  return useQuery({
    queryKey,
    queryFn: ({ signal }) => queryFn(signal),
    enabled: hasCapture && gate && enabled,
    staleTime: CAPTURE_STALE,
    ...rest,
  } satisfies UseQueryOptions<T>)
}

function useLiveQuery<T>(
  queryKey: readonly unknown[],
  queryFn: (signal: AbortSignal) => Promise<T>,
  extra: Extra<T> = {}
) {
  // La clave la arma cada hook con sus parámetros; queryFn recibe el cierre equivalente.
  // eslint-disable-next-line @tanstack/query/exhaustive-deps
  return useQuery({
    queryKey,
    queryFn: ({ signal }) => queryFn(signal),
    staleTime: LIVE_STALE,
    ...extra,
  } satisfies UseQueryOptions<T>)
}

/* ------------------------------- captura cargada ------------------------------ */

export const useSessions = (filters: SessionFilters = {}, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.sessions(generation, filters),
    (s) => api.sessions(filters, s),
    extra
  )
}
export const useStats = (filters: SessionFilters = {}, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.stats(generation, filters),
    (s) => api.stats(filters, s),
    extra
  )
}
export const useTimeline = (extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.timeline(generation),
    (s) => api.timeline(s),
    extra
  )
}
export const useAlerts = (severity?: string, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.alerts(generation, severity),
    (s) => api.alerts(severity, s),
    extra
  )
}
export const useHosts = (limit?: number, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.hosts(generation, limit),
    (s) => api.hosts(limit, s),
    extra
  )
}
export const useHostsByMac = (extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.hostsByMac(generation),
    (s) => api.hostsByMac(s),
    extra
  )
}
export const useGraph = (limit?: number, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.graph(generation, limit),
    (s) => api.graph(limit, s),
    extra
  )
}
export const useDns = (q?: string, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(keys.dns(generation, q), (s) => api.dns(q, s), extra)
}
export const useHttpOverview = (extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.http(generation),
    (s) => api.httpOverview(s),
    extra
  )
}
export const useCaseTimeline = (host?: string, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.caseTimeline(generation, host),
    (s) => api.caseTimeline(host, s),
    extra
  )
}
export const useRemoteAccess = (service?: string, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.remote(generation, service),
    (s) => api.remoteAccess(service, s),
    extra
  )
}
export const useWiresharkFilter = (ip: string, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.wiresharkFilter(generation, ip),
    (s) => api.wiresharkFilter(ip, s),
    {
      gate: ip !== '',
      ...extra,
    }
  )
}

/* ----------------------- detalle de sesión y de paquete ----------------------- */
// `id` null/undefined = ninguna sesión seleccionada: la query no corre.

type SessionId = string | number | null | undefined
const hasId = (id: SessionId): id is string | number =>
  id !== null && id !== undefined && id !== ''

export const useExplain = (id: SessionId, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.session(generation, id ?? '', 'explain'),
    (s) => api.explain(id as string | number, s),
    { gate: hasId(id), ...extra }
  )
}
export const useSessionHttp = (id: SessionId, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.session(generation, id ?? '', 'http'),
    (s) => api.sessionHttp(id as string | number, s),
    { gate: hasId(id), ...extra }
  )
}
export const useSessionTls = (id: SessionId, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.session(generation, id ?? '', 'tls'),
    (s) => api.sessionTls(id as string | number, s),
    { gate: hasId(id), ...extra }
  )
}
export const useSessionPackets = (
  id: SessionId,
  params: { limit?: number; offset?: number } = {},
  extra?: Extra
) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.session(generation, id ?? '', 'packets', params),
    (s) => api.sessionPackets(id as string | number, params, s),
    { gate: hasId(id), ...extra }
  )
}
export const useStream = (id: SessionId, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.session(generation, id ?? '', 'stream'),
    (s) => api.stream(id as string | number, s),
    { gate: hasId(id), ...extra }
  )
}
export const usePacket = (index: SessionId, extra?: Extra) => {
  const { generation } = useCapture()
  return useCaptureQuery(
    keys.packet(generation, index ?? ''),
    (s) => api.packet(index as string | number, s),
    { gate: hasId(index), ...extra }
  )
}

/* ------------------------ reglas, IOC y captura en vivo ----------------------- */
// Reglas e IOC viven en el backend, con o sin captura cargada.

export const useRules = (extra?: Extra) =>
  useLiveQuery(keys.rules, (s) => api.rules(s), extra)
export const useIocs = (extra?: Extra) =>
  useLiveQuery(keys.iocs, (s) => api.iocs(s), extra)
export const useInterfaces = (extra?: Extra) =>
  useLiveQuery(keys.interfaces, (s) => api.interfaces(s), {
    staleTime: CAPTURE_STALE,
    ...extra,
  })
/** Estado de la captura en vivo; pasá `refetchInterval` (ms) mientras corre. */
export const useLiveStatus = (extra?: Extra<LiveStatus>) =>
  useLiveQuery(keys.live, (s) => api.liveStatus(s), extra)

/* ------------------------------ soporte: sistema ------------------------------ */

export const useSystemOverview = (extra?: Extra) =>
  useLiveQuery(keys.system('overview'), (s) => api.systemOverview(s), extra)
export const useProcesses = (
  params: { sort?: string; limit?: number } = {},
  extra?: Extra
) =>
  useLiveQuery(
    keys.system('processes', params),
    (s) => api.systemProcesses(params, s),
    extra
  )
export const useProcess = (pid: SessionId, extra?: Extra) =>
  useLiveQuery(
    keys.system('process', pid),
    (s) => api.systemProcess(pid as string | number, s),
    {
      enabled: hasId(pid),
      ...extra,
    }
  )
export const useProcessFile = (pid: SessionId, extra?: Extra) =>
  useLiveQuery(
    keys.system('process-file', pid),
    (s) => api.systemProcessFile(pid as string | number, s),
    {
      enabled: hasId(pid),
      ...extra,
    }
  )
export const usePorts = (extra?: Extra) =>
  useLiveQuery(keys.system('ports'), (s) => api.systemPorts(s), extra)
export const useConnections = (extra?: Extra) =>
  useLiveQuery(
    keys.system('connections'),
    (s) => api.systemConnections(s),
    extra
  )
export const useServices = (extra?: Extra) =>
  useLiveQuery(keys.system('services'), (s) => api.systemServices(s), extra)
export const useStartup = (extra?: Extra) =>
  useLiveQuery(keys.system('startup'), (s) => api.systemStartup(s), extra)

/* -------------------------------- soporte: red -------------------------------- */
// Las pruebas que salen a la red (internet, latencia, ping...) son mutations: ver mutations.ts.

export const useNetConfig = (extra?: Extra) =>
  useLiveQuery(keys.support('config'), (s) => api.supportConfig(s), extra)
export const useNetConfigRaw = (extra?: Extra) =>
  useLiveQuery(
    keys.support('config-raw'),
    (s) => api.supportConfigRaw(s),
    extra
  )
export const useWifi = (extra?: Extra) =>
  useLiveQuery(keys.support('wifi'), (s) => api.supportWifi(s), extra)
export const useWifiHistory = (extra?: Extra) =>
  useLiveQuery(
    keys.support('wifi-history'),
    (s) => api.supportWifiHistory(s),
    extra
  )
/** Monitoreo de cortes; usá `refetchInterval` mientras `running`. */
export const useMonitorStatus = (extra?: Extra<MonitorStatus>) =>
  useLiveQuery(keys.support('monitor'), (s) => api.monitorStatus(s), extra)
