// Cliente de la API: request() con el token, errores tipados y validación con zod.
import { type z } from 'zod'
import * as S from './schemas'
import { getToken } from './token'

/** Error HTTP de la API. `status` 0 = no se pudo conectar. */
export class ApiError extends Error {
  status: number
  detail: string
  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
  /** 401: falta o no vale el token. */
  get isAuth() {
    return this.status === 401
  }
  /** 403: p. ej. ruta fuera de las carpetas permitidas (el mensaje se muestra tal cual). */
  get isForbidden() {
    return this.status === 403
  }
  /** 422: validación de la API. */
  get isValidation() {
    return this.status === 422
  }
  /** 409: no hay captura cargada. */
  get isNoCapture() {
    return this.status === 409
  }
}

/** La respuesta llegó bien pero no calza con el esquema esperado (no es culpa del usuario). */
export class ApiSchemaError extends Error {
  path: string
  issues: string
  constructor(path: string, issues: string) {
    super(
      `La respuesta de ${path} no tiene la forma esperada (${issues}). ` +
        'Puede que el backend y la interfaz sean de versiones distintas.'
    )
    this.name = 'ApiSchemaError'
    this.path = path
    this.issues = issues
  }
}

type FastApiIssue = { loc?: unknown[]; msg?: string }

// FastAPI responde `detail` como texto (nuestros errores) o como lista (validación)
export function normalizeDetail(detail: unknown): string | null {
  if (detail == null) return null
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return (detail as FastApiIssue[])
      .map((d) => {
        const where = Array.isArray(d.loc)
          ? d.loc.filter((p) => p !== 'query' && p !== 'body').join('.')
          : ''
        const msg = d.msg ?? JSON.stringify(d)
        return where ? `${where}: ${msg}` : msg
      })
      .join('; ')
  }
  return JSON.stringify(detail)
}

type Primitive = string | number | boolean | null | undefined

// Arma "?a=1&b=2" omitiendo valores vacíos (null, undefined, ""), así un filtro vacío no viaja
export function buildQuery(params: Record<string, Primitive> = {}): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === '') continue
    q.append(k, String(v))
  }
  const s = q.toString()
  return s ? `?${s}` : ''
}

function tokenHeader(): Record<string, string> {
  const token = getToken()
  return token ? { 'X-Tracewell-Token': token } : {}
}

function describeIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 3)
    .map((i) => `${i.path.join('.') || 'raíz'}: ${i.message}`)
    .join('; ')
}

type RequestOptions<T extends z.ZodType> = {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
  signal?: AbortSignal
  schema: T
}

export async function request<T extends z.ZodType>(
  path: string,
  { method = 'GET', body, signal, schema }: RequestOptions<T>
): Promise<z.output<T>> {
  const headers: Record<string, string> = {
    ...(body ? { 'Content-Type': 'application/json' } : {}),
    ...tokenHeader(),
  }
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal,
    })
  } catch (e) {
    if ((e as { name?: string })?.name === 'AbortError') throw e
    throw new ApiError(0, 'No se pudo conectar con la API. ¿Está en marcha?')
  }
  if (!res.ok) {
    let detail = res.statusText || `Error ${res.status}`
    try {
      const j = await res.json()
      detail = normalizeDetail(j?.detail) ?? detail
    } catch {
      /* cuerpo no JSON: nos quedamos con el statusText */
    }
    throw new ApiError(res.status, detail)
  }
  let json: unknown
  try {
    json = await res.json()
  } catch {
    throw new ApiSchemaError(path, 'la respuesta no es JSON')
  }
  const parsed = schema.safeParse(json)
  if (!parsed.success) {
    throw new ApiSchemaError(path, describeIssues(parsed.error))
  }
  return parsed.data
}

const id = (value: string | number) => encodeURIComponent(value)

export type SessionFilters = {
  protocol?: string
  ip?: string
  port?: number | string
  limit?: number
  offset?: number
}
export type LiveStartBody = {
  interface: string
  max_seconds?: number | null
  max_packets?: number | null
}
export type RuleBody = {
  name: string
  severity?: S.Severity
  description?: string
  protocol?: string
  src_ip?: string
  dst_ip?: string
  port?: number
  min_events?: number
  window_seconds?: number
  id?: string
  mitre_technique?: string
  mitre_name?: string
  mitre_tactic?: string
}
export type NoteBody = { note: string; reviewed: boolean }

const get = <T extends z.ZodType>(
  path: string,
  schema: T,
  signal?: AbortSignal
) => request(path, { schema, signal })
const post = <T extends z.ZodType>(
  path: string,
  schema: T,
  signal?: AbortSignal,
  body?: unknown
) => request(path, { method: 'POST', schema, signal, body })

/** Todos los endpoints de la API, con su método, su URL y el esquema de su respuesta. */
export const api = {
  health: (signal?: AbortSignal) => get('/api/health', S.healthSchema, signal),
  // Captura cargada
  demo: () => post('/api/demo', S.captureSchema),
  analyze: (path: string) =>
    request('/api/analyze', {
      method: 'POST',
      body: { path },
      schema: S.captureSchema,
    }),
  capture: (signal?: AbortSignal) =>
    get('/api/capture', S.captureSchema, signal),
  closeCapture: () =>
    request('/api/capture', { method: 'DELETE', schema: S.clearedSchema }),
  stats: (filters: SessionFilters = {}, signal?: AbortSignal) =>
    get(`/api/stats${buildQuery(filters)}`, S.statsSchema, signal),
  sessions: (params: SessionFilters = {}, signal?: AbortSignal) =>
    get(`/api/sessions${buildQuery(params)}`, S.sessionsPageSchema, signal),
  timeline: (signal?: AbortSignal) =>
    get('/api/timeline', S.timelineSchema, signal),
  alerts: (severity?: string, signal?: AbortSignal) =>
    get(`/api/alerts${buildQuery({ severity })}`, S.alertsSchema, signal),
  // Entender la captura
  hosts: (limit?: number, signal?: AbortSignal) =>
    get(`/api/hosts${buildQuery({ limit })}`, S.hostsSchema, signal),
  hostsByMac: (signal?: AbortSignal) =>
    get('/api/hosts/by-mac', S.hostsByMacSchema, signal),
  graph: (limit?: number, signal?: AbortSignal) =>
    get(`/api/graph${buildQuery({ limit })}`, S.graphSchema, signal),
  dns: (q?: string, signal?: AbortSignal) =>
    get(`/api/dns${buildQuery({ q })}`, S.dnsSchema, signal),
  httpOverview: (signal?: AbortSignal) =>
    get('/api/http', S.httpOverviewSchema, signal),
  caseTimeline: (host?: string, signal?: AbortSignal) =>
    get(
      `/api/case-timeline${buildQuery({ host })}`,
      S.caseTimelineSchema,
      signal
    ),
  remoteAccess: (service?: string, signal?: AbortSignal) =>
    get(
      `/api/remote-access${buildQuery({ service })}`,
      S.remoteAccessSchema,
      signal
    ),
  wiresharkFilter: (ip: string, signal?: AbortSignal) =>
    get(
      `/api/wireshark-filter${buildQuery({ ip })}`,
      S.wiresharkFilterSchema,
      signal
    ),
  // Detalle de una sesión y de un paquete
  explain: (sessionId: string | number, signal?: AbortSignal) =>
    get(`/api/sessions/${id(sessionId)}/explain`, S.explainSchema, signal),
  sessionHttp: (sessionId: string | number, signal?: AbortSignal) =>
    get(`/api/sessions/${id(sessionId)}/http`, S.sessionHttpSchema, signal),
  sessionTls: (sessionId: string | number, signal?: AbortSignal) =>
    get(`/api/sessions/${id(sessionId)}/tls`, S.tlsSchema, signal),
  sessionPackets: (
    sessionId: string | number,
    params: { limit?: number; offset?: number } = {},
    signal?: AbortSignal
  ) =>
    get(
      `/api/sessions/${id(sessionId)}/packets${buildQuery(params)}`,
      S.packetsPageSchema,
      signal
    ),
  stream: (sessionId: string | number, signal?: AbortSignal) =>
    get(`/api/sessions/${id(sessionId)}/stream`, S.streamSchema, signal),
  packet: (index: string | number, signal?: AbortSignal) =>
    get(`/api/packets/${id(index)}`, S.packetDetailSchema, signal),
  // Captura en vivo
  interfaces: (signal?: AbortSignal) =>
    get('/api/interfaces', S.interfacesSchema, signal),
  liveStart: (body: LiveStartBody) =>
    request('/api/live/start', {
      method: 'POST',
      body,
      schema: S.liveStatusSchema,
    }),
  liveStatus: (signal?: AbortSignal) =>
    get('/api/live/status', S.liveStatusSchema, signal),
  liveStop: () => post('/api/live/stop', S.captureSchema),
  // Descargas: devolvemos la URL para un <a download> (ver ticketUrl).
  exportUrl: (filters: SessionFilters = {}) =>
    `/api/export${buildQuery(filters)}`,
  reportUrl: () => '/api/report',
  httpBodyUrl: (sessionId: string | number, index: string | number) =>
    `/api/sessions/${id(sessionId)}/http/${id(index)}/body`,
  sessionPcapUrl: (sessionId: string | number) =>
    `/api/sessions/${id(sessionId)}/pcap`,
  filteredPcapUrl: (filters: SessionFilters = {}) =>
    `/api/pcap${buildQuery(filters)}`,
  // Un <a download> no lleva cabeceras: se pide un ticket de un solo uso y se agrega a la URL.
  ticketUrl: async (url: string) => {
    const path = url.split('?')[0]
    const { ticket, query } = await request('/api/download-ticket', {
      method: 'POST',
      body: { path },
      schema: S.downloadTicketSchema,
    })
    return `${url}${url.includes('?') ? '&' : '?'}${query}=${encodeURIComponent(ticket)}`
  },
  // Triaje: nota/marca "revisada" por sesión, reglas y lista de indicadores de compromiso (IOC).
  saveNote: (sessionId: string | number, body: NoteBody) =>
    request(`/api/sessions/${id(sessionId)}/note`, {
      method: 'PUT',
      body,
      schema: S.noteSchema,
    }),
  rules: (signal?: AbortSignal) => get('/api/rules', S.rulesSchema, signal),
  previewRule: (body: RuleBody, signal?: AbortSignal) =>
    post('/api/rules/preview', S.rulePreviewSchema, signal, body),
  saveRule: (body: RuleBody) =>
    post('/api/rules', S.savedRuleSchema, undefined, body),
  iocs: (signal?: AbortSignal) => get('/api/iocs', S.iocStatusSchema, signal),
  loadIocs: (path: string) =>
    request('/api/iocs', {
      method: 'POST',
      body: { path },
      schema: S.iocStatusSchema,
    }),
  clearIocs: () =>
    request('/api/iocs', { method: 'DELETE', schema: S.iocStatusSchema }),
  // Soporte de red → Sistema: todo de SOLO LECTURA sobre el equipo donde corre Tracewell.
  systemOverview: (signal?: AbortSignal) =>
    get('/api/system/overview', S.systemOverviewSchema, signal),
  systemProcesses: (
    params: { sort?: string; limit?: number } = {},
    signal?: AbortSignal
  ) =>
    get(
      `/api/system/processes${buildQuery(params)}`,
      S.processesSchema,
      signal
    ),
  systemProcess: (pid: string | number, signal?: AbortSignal) =>
    get(`/api/system/processes/${id(pid)}`, S.processDetailSchema, signal),
  systemProcessFile: (pid: string | number, signal?: AbortSignal) =>
    get(`/api/system/processes/${id(pid)}/file`, S.processFileSchema, signal),
  systemPorts: (signal?: AbortSignal) =>
    get('/api/system/ports', S.portsSchema, signal),
  systemConnections: (signal?: AbortSignal) =>
    get('/api/system/connections', S.connectionsSchema, signal),
  systemServices: (signal?: AbortSignal) =>
    get('/api/system/services', S.servicesSchema, signal),
  systemStartup: (signal?: AbortSignal) =>
    get('/api/system/startup', S.startupSchema, signal),
  // Soporte de red → Red: pruebas de solo lectura (las que salen a la red son POST)
  supportConfig: (signal?: AbortSignal) =>
    get('/api/support/config', S.netConfigSchema, signal),
  supportConfigRaw: (signal?: AbortSignal) =>
    get('/api/support/config/raw', S.netConfigRawSchema, signal),
  supportInternet: (signal?: AbortSignal) =>
    post('/api/support/internet', S.internetCheckSchema, signal),
  supportLatency: (
    params: { host?: string; port?: number; samples?: number } = {},
    signal?: AbortSignal
  ) =>
    post(`/api/support/latency${buildQuery(params)}`, S.latencySchema, signal),
  supportPing: (host: string, count?: number, signal?: AbortSignal) =>
    post(
      `/api/support/ping${buildQuery({ host, count })}`,
      S.pingSchema,
      signal
    ),
  supportTraceroute: (host: string, signal?: AbortSignal) =>
    post(
      `/api/support/traceroute${buildQuery({ host })}`,
      S.toolResultSchema,
      signal
    ),
  supportPorts: (host: string, ports?: string, signal?: AbortSignal) =>
    post(
      `/api/support/ports${buildQuery({ host, ports })}`,
      S.portScanSchema,
      signal
    ),
  supportRdp: (host: string, port?: number, signal?: AbortSignal) =>
    post(
      `/api/support/rdp${buildQuery({ host, port })}`,
      S.toolResultSchema,
      signal
    ),
  supportTime: (server?: string, signal?: AbortSignal) =>
    post(
      `/api/support/time${buildQuery({ server })}`,
      S.toolResultSchema,
      signal
    ),
  supportDevices: (scan?: boolean, signal?: AbortSignal) =>
    post(
      `/api/support/devices${buildQuery({ scan: scan ? 'true' : '' })}`,
      S.toolResultSchema,
      signal
    ),
  supportWifi: (signal?: AbortSignal) =>
    get('/api/support/wifi', S.wifiSchema, signal),
  supportWifiHistory: (signal?: AbortSignal) =>
    get('/api/support/wifi/history', S.wifiHistorySchema, signal),
  supportDuplicateIp: (signal?: AbortSignal) =>
    post('/api/support/duplicate-ip', S.duplicateIpSchema, signal),
  monitorStatus: (signal?: AbortSignal) =>
    get('/api/support/monitor', S.monitorSchema, signal),
  monitorStart: (interval?: number) =>
    post(
      `/api/support/monitor/start${buildQuery({ interval })}`,
      S.monitorSchema
    ),
  monitorStop: () => post('/api/support/monitor/stop', S.monitorSchema),
  monitorClear: () => post('/api/support/monitor/clear', S.monitorSchema),
}
