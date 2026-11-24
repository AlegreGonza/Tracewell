// Handlers de MSW: un endpoint por ruta de la API con los datos de ./fixtures.
// En una prueba, `server.use(http.get('/api/...', ...))` reemplaza un handler solo para ese caso
// (se restablecen solos después de cada prueba).
import { http, HttpResponse, type JsonBodyType } from 'msw'
import { fixtures } from './fixtures'

/** Estado del backend simulado (se restablece después de cada prueba). */
export const mockState = {
  loaded: false,
  notes: new Map<string, { note: string; reviewed: boolean }>(),
}

export function resetMockState() {
  mockState.loaded = false
  mockState.notes.clear()
}

/** Respuesta de error como la de FastAPI: `{ detail }`. */
export const apiError = (status: number, detail: unknown) =>
  HttpResponse.json({ detail }, { status })

const noCapture = () =>
  apiError(
    409,
    'no hay una captura analizada: usá /api/analyze, /api/demo o la captura en vivo'
  )

/** GET que responde 409 (sin captura) hasta que se analiza algo; `always` ignora ese estado. */
const captureGet = (path: string, body: JsonBodyType) =>
  http.get(path, () =>
    mockState.loaded ? HttpResponse.json(body) : noCapture()
  )

const json = (
  path: string,
  body: JsonBodyType,
  method: 'get' | 'post' = 'get'
) => http[method](path, () => HttpResponse.json(body))

export const handlers = [
  json('/api/health', fixtures.health),
  // Captura cargada
  http.post('/api/demo', () => {
    mockState.loaded = true
    return HttpResponse.json(fixtures.capture)
  }),
  http.post('/api/analyze', async ({ request }) => {
    const { path } = (await request.json()) as { path?: string }
    if (!path)
      return apiError(422, [{ loc: ['body', 'path'], msg: 'requerido' }])
    mockState.loaded = true
    return HttpResponse.json({
      ...fixtures.capture,
      source: path.split(/[\\/]/).pop(),
    })
  }),
  captureGet('/api/capture', fixtures.capture),
  http.delete('/api/capture', () => {
    mockState.loaded = false
    return HttpResponse.json({ cleared: true })
  }),
  captureGet('/api/stats', fixtures.stats),
  captureGet('/api/sessions', fixtures.sessions),
  captureGet('/api/timeline', fixtures.timeline),
  captureGet('/api/alerts', fixtures.alerts),
  captureGet('/api/hosts', fixtures.hosts),
  captureGet('/api/hosts/by-mac', fixtures.hostsByMac),
  captureGet('/api/graph', fixtures.graph),
  captureGet('/api/dns', fixtures.dns),
  captureGet('/api/http', fixtures.http),
  captureGet('/api/remote-access', fixtures.remoteAccess),
  captureGet('/api/case-timeline', fixtures.caseTimeline),
  captureGet('/api/wireshark-filter', fixtures.wiresharkFilter),
  captureGet('/api/sessions/:id/explain', fixtures.explain),
  captureGet('/api/sessions/:id/http', fixtures.sessionHttp),
  captureGet('/api/sessions/:id/tls', fixtures.sessionTls),
  captureGet('/api/sessions/:id/packets', fixtures.sessionPackets),
  captureGet('/api/sessions/:id/stream', fixtures.stream),
  captureGet('/api/packets/:index', fixtures.packet),
  // Captura en vivo
  json('/api/interfaces', fixtures.interfaces),
  json('/api/live/status', fixtures.liveStatus),
  http.post('/api/live/start', () =>
    HttpResponse.json({ ...fixtures.liveStatus, state: 'running' })
  ),
  http.post('/api/live/stop', () => {
    mockState.loaded = true
    return HttpResponse.json(fixtures.capture)
  }),
  // Descargas, triaje, reglas e IOC
  http.post('/api/download-ticket', () =>
    HttpResponse.json({ ticket: 'ticket-de-prueba', query: 'ticket' })
  ),
  http.put('/api/sessions/:id/note', async ({ params, request }) => {
    const body = (await request.json()) as { note: string; reviewed: boolean }
    mockState.notes.set(String(params.id), body)
    return HttpResponse.json({ id: Number(params.id), ...body })
  }),
  json('/api/rules', fixtures.rules),
  json('/api/rules/preview', fixtures.rulePreview, 'post'),
  http.post('/api/rules', () =>
    HttpResponse.json({ id: 'regla-nueva', custom: true }, { status: 201 })
  ),
  json('/api/iocs', fixtures.iocs),
  http.post('/api/iocs', () =>
    HttpResponse.json({
      loaded: true,
      source: 'lista.txt',
      ips: 2,
      networks: 0,
      domains: 1,
      sessions: 3,
    })
  ),
  http.delete('/api/iocs', () => HttpResponse.json(fixtures.iocs)),
  // Soporte de red → Sistema
  json('/api/system/overview', fixtures.systemOverview),
  json('/api/system/processes', fixtures.processes),
  json('/api/system/processes/:pid', fixtures.process),
  json('/api/system/processes/:pid/file', fixtures.processFile),
  json('/api/system/ports', fixtures.ports),
  json('/api/system/connections', fixtures.connections),
  json('/api/system/services', fixtures.services),
  json('/api/system/startup', fixtures.startup),
  // Soporte de red → Red
  json('/api/support/config', fixtures.netConfig),
  json('/api/support/config/raw', fixtures.netConfigRaw),
  json('/api/support/wifi', fixtures.wifi),
  json('/api/support/wifi/history', fixtures.wifiHistory),
  json('/api/support/monitor', fixtures.monitor),
  json(
    '/api/support/monitor/start',
    { ...fixtures.monitor, running: true },
    'post'
  ),
  json('/api/support/monitor/stop', fixtures.monitor, 'post'),
  json('/api/support/monitor/clear', fixtures.monitor, 'post'),
  json('/api/support/internet', fixtures.internet, 'post'),
  json('/api/support/latency', fixtures.latency, 'post'),
  json('/api/support/ping', fixtures.ping, 'post'),
  json('/api/support/traceroute', fixtures.traceroute, 'post'),
  json('/api/support/ports', fixtures.portScan, 'post'),
  json('/api/support/rdp', fixtures.rdp, 'post'),
  json('/api/support/time', fixtures.time, 'post'),
  json('/api/support/devices', fixtures.devices, 'post'),
  json('/api/support/duplicate-ip', fixtures.duplicateIp, 'post'),
]
