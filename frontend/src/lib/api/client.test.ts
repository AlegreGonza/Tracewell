import { fixtures } from '@/test/fixtures'
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import {
  api,
  ApiError,
  ApiSchemaError,
  buildQuery,
  normalizeDetail,
} from './client'
import { setToken } from './token'

// Estas pruebas miran el pedido que sale (URL, método, cuerpo, cabeceras) con fetch simulado.
const reply = (status: number, body: unknown, statusText = '') =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    statusText,
    headers: { 'Content-Type': 'application/json' },
  })

let fetchMock: Mock<typeof fetch>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

const last = () => fetchMock.mock.calls.at(-1)! as [string, RequestInit]
const respondWith = (body: unknown) =>
  fetchMock.mockImplementation(async () => reply(200, body))
const failWith = (status: number, body: unknown, statusText = '') =>
  fetchMock.mockImplementation(async () => reply(status, body, statusText))

// Con respuestas {} el esquema falla: acá solo importa el pedido que salió.
const call = async (p: Promise<unknown>) => {
  await p.catch(() => undefined)
  return last()
}

describe('normalizeDetail', () => {
  it('string tal cual', () => expect(normalizeDetail('hola')).toBe('hola'))
  it('null/undefined -> null', () => {
    expect(normalizeDetail(null)).toBeNull()
    expect(normalizeDetail(undefined)).toBeNull()
  })
  it('lista de validación con loc (quita query/body)', () => {
    expect(
      normalizeDetail([{ loc: ['query', 'port'], msg: 'fuera de rango' }])
    ).toBe('port: fuera de rango')
    expect(
      normalizeDetail([
        { loc: ['body', 'path'], msg: 'requerido' },
        { loc: ['query', 'ip'], msg: 'inválida' },
      ])
    ).toBe('path: requerido; ip: inválida')
  })
  it('elemento sin loc usa solo msg; sin msg serializa', () => {
    expect(normalizeDetail([{ msg: 'x' }])).toBe('x')
    expect(normalizeDetail([{ loc: [] }])).toBe('{"loc":[]}')
  })
  it('objeto -> JSON', () => expect(normalizeDetail({ a: 1 })).toBe('{"a":1}'))
  it('lista vacía -> cadena vacía', () => expect(normalizeDetail([])).toBe(''))
})

describe('buildQuery', () => {
  it('vacío -> ""', () => {
    expect(buildQuery()).toBe('')
    expect(buildQuery({})).toBe('')
    expect(buildQuery({ a: null, b: undefined, c: '' })).toBe('')
  })
  it('omite vacíos pero conserva 0 y false', () => {
    expect(buildQuery({ a: 0, b: false, c: '', d: null, e: 'x' })).toBe(
      '?a=0&b=false&e=x'
    )
  })
  it('escapa caracteres especiales y unicode', () => {
    const q = buildQuery({ q: 'a b&c=d/é#' })
    expect(q).toBe('?q=a+b%26c%3Dd%2F%C3%A9%23')
    expect(new URLSearchParams(q).get('q')).toBe('a b&c=d/é#')
  })
})

describe('request y errores', () => {
  it('éxito devuelve el JSON validado', async () => {
    respondWith(fixtures.alerts)
    const alerts = await api.alerts()
    expect(alerts).toHaveLength(3)
    expect(alerts[0].mitre_technique).toBe('T1040')
  })

  it.each([404, 409, 422, 500])('error %i con JSON string', async (st) => {
    failWith(st, { detail: 'algo falló' })
    const err = await api.capture().catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(st)
    expect(err.message).toBe('algo falló')
    expect(err.detail).toBe('algo falló')
  })

  it('401 y 403 se distinguen y el mensaje del 403 llega tal cual', async () => {
    const detail =
      'la ruta está fuera de las carpetas permitidas (Descargas, Documentos)'
    fetchMock.mockImplementationOnce(async () => reply(403, { detail }))
    const forbidden = await api.analyze('C:\\x.pcap').catch((e) => e)
    expect(forbidden.isForbidden).toBe(true)
    expect(forbidden.message).toBe(detail)
    fetchMock.mockImplementationOnce(async () =>
      reply(401, { detail: 'falta el token' })
    )
    const auth = await api.capture().catch((e) => e)
    expect(auth.isAuth).toBe(true)
  })

  it('422 con lista de validación', async () => {
    failWith(422, { detail: [{ loc: ['query', 'port'], msg: 'inválido' }] })
    const err = await api.sessions({ port: 99999 }).catch((e) => e)
    expect(err.isValidation).toBe(true)
    expect(err.message).toBe('port: inválido')
  })

  it('409 es "sin captura"', async () => {
    failWith(409, { detail: 'no hay una captura analizada' })
    const err = await api.sessions().catch((e) => e)
    expect(err.isNoCapture).toBe(true)
  })

  it('cuerpo no JSON usa statusText', async () => {
    failWith(502, 'no es json', 'Bad Gateway')
    const err = await api.capture().catch((e) => e)
    expect(err.status).toBe(502)
    expect(err.message).toBe('Bad Gateway')
  })

  it('sin statusText ni JSON -> "Error N"', async () => {
    failWith(500, 'x', '')
    const err = await api.capture().catch((e) => e)
    expect(err.message).toBe('Error 500')
  })

  it('JSON sin detail usa statusText', async () => {
    failWith(500, {}, 'Internal Server Error')
    const err = await api.capture().catch((e) => e)
    expect(err.message).toBe('Internal Server Error')
  })

  it('fallo de red -> ApiError status 0 legible', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const err = await api.capture().catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(0)
    expect(err.message).toMatch(/No se pudo conectar/)
  })

  it('AbortError se propaga sin envolver', async () => {
    const abort = new DOMException('abortado', 'AbortError')
    fetchMock.mockRejectedValue(abort)
    const err = await api.capture().catch((e) => e)
    expect(err).toBe(abort)
    expect(err).not.toBeInstanceOf(ApiError)
  })

  it('pasa la señal a fetch', async () => {
    respondWith(fixtures.capture)
    const ctl = new AbortController()
    await api.capture(ctl.signal)
    expect(last()[1].signal).toBe(ctl.signal)
  })
})

describe('validación con zod: nunca pantalla en blanco', () => {
  it('una respuesta que no calza lanza ApiSchemaError con un mensaje claro', async () => {
    respondWith({ total: 'muchas', items: [] })
    const err = await api.sessions().catch((e) => e)
    expect(err).toBeInstanceOf(ApiSchemaError)
    expect(err.message).toMatch(/\/api\/sessions/)
    expect(err.message).toMatch(/total/)
  })

  it('una respuesta que no es JSON también', async () => {
    fetchMock.mockImplementation(async () => reply(200, '<html>hola</html>'))
    await expect(api.timeline()).rejects.toBeInstanceOf(ApiSchemaError)
  })

  it('tolera campos nuevos del backend y datos opcionales ausentes', async () => {
    const sinFecha: Record<string, unknown> = { ...fixtures.alerts[0] }
    delete sinFecha.first_ts
    respondWith([{ ...sinFecha, campo_nuevo: 1 }])
    const [a] = await api.alerts()
    expect((a as Record<string, unknown>).campo_nuevo).toBe(1)
  })

  it('una severidad desconocida es un error de esquema, no un dato silencioso', async () => {
    respondWith([{ ...fixtures.alerts[0], severity: 'enorme' }])
    await expect(api.alerts()).rejects.toBeInstanceOf(ApiSchemaError)
  })
})

describe('token en cada pedido', () => {
  it('manda X-Tracewell-Token si hay token', async () => {
    setToken('secreto')
    respondWith(fixtures.capture)
    await api.capture()
    expect(last()[1].headers).toEqual({ 'X-Tracewell-Token': 'secreto' })
  })

  it('con cuerpo suma Content-Type y mantiene el token', async () => {
    setToken('secreto')
    respondWith(fixtures.capture)
    await api.analyze('C:\\caps\\a.pcap')
    expect(last()[1].headers).toEqual({
      'Content-Type': 'application/json',
      'X-Tracewell-Token': 'secreto',
    })
  })

  it('sin token no manda cabeceras', async () => {
    respondWith(fixtures.capture)
    await api.capture()
    expect(last()[1].headers).toBeUndefined()
  })
})

describe('métodos, URLs y cuerpos', () => {
  beforeEach(() => respondWith({}))

  it('analyze: POST /api/analyze con {path} y Content-Type', async () => {
    const [url, opts] = await call(api.analyze('C:\\caps\\a.pcap'))
    expect(url).toBe('/api/analyze')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body as string)).toEqual({
      path: 'C:\\caps\\a.pcap',
    })
    expect(opts.headers).toEqual({ 'Content-Type': 'application/json' })
  })
  it('demo: POST sin cuerpo', async () => {
    const [url, opts] = await call(api.demo())
    expect(url).toBe('/api/demo')
    expect(opts.method).toBe('POST')
    expect(opts.body).toBeUndefined()
    expect(opts.headers).toBeUndefined()
  })
  it('capture/interfaces/liveStatus son GET', async () => {
    let [url, opts] = await call(api.capture())
    expect([url, opts.method]).toEqual(['/api/capture', 'GET'])
    ;[url, opts] = await call(api.interfaces())
    expect([url, opts.method]).toEqual(['/api/interfaces', 'GET'])
    ;[url, opts] = await call(api.liveStatus())
    expect([url, opts.method]).toEqual(['/api/live/status', 'GET'])
  })
  it('liveStart POST con cuerpo; liveStop POST', async () => {
    const [url, opts] = await call(api.liveStart({ interface: 'eth0' }))
    expect(url).toBe('/api/live/start')
    expect(JSON.parse(opts.body as string)).toEqual({ interface: 'eth0' })
    const [stopUrl, stopOpts] = await call(api.liveStop())
    expect([stopUrl, stopOpts.method]).toEqual(['/api/live/stop', 'POST'])
  })
  it('sessions arma la query omitiendo vacíos y conservando 0', async () => {
    const [url] = await call(
      api.sessions({ protocol: 'TCP', ip: '', port: 0, limit: 25, offset: 0 })
    )
    expect(url).toBe('/api/sessions?protocol=TCP&port=0&limit=25&offset=0')
  })
  it('alerts con y sin severidad', async () => {
    expect((await call(api.alerts('high')))[0]).toBe(
      '/api/alerts?severity=high'
    )
    expect((await call(api.alerts(undefined)))[0]).toBe('/api/alerts')
  })
  it('sessionPackets y packet codifican el id', async () => {
    expect(
      (await call(api.sessionPackets('a/b c?', { limit: 50, offset: 0 })))[0]
    ).toBe('/api/sessions/a%2Fb%20c%3F/packets?limit=50&offset=0')
    expect((await call(api.packet('1/../2')))[0]).toBe(
      '/api/packets/1%2F..%2F2'
    )
    expect((await call(api.packet(7)))[0]).toBe('/api/packets/7')
  })
  it('stream codifica el id, usa GET y pasa la señal', async () => {
    const ctl = new AbortController()
    const [url, opts] = await call(api.stream('a/b c?', ctl.signal))
    expect(url).toBe('/api/sessions/a%2Fb%20c%3F/stream')
    expect(opts.signal).toBe(ctl.signal)
    expect(opts.method).toBe('GET')
  })
  it('stream propaga el mensaje de error del servidor', async () => {
    fetchMock.mockImplementationOnce(async () =>
      reply(422, { detail: 'solo las sesiones TCP' })
    )
    await expect(api.stream(1)).rejects.toMatchObject({
      status: 422,
      message: 'solo las sesiones TCP',
    })
  })
  it('closeCapture hace DELETE /api/capture', async () => {
    fetchMock.mockImplementationOnce(async () => reply(200, { cleared: true }))
    await expect(api.closeCapture()).resolves.toEqual({ cleared: true })
    expect([last()[0], last()[1].method]).toEqual(['/api/capture', 'DELETE'])
  })
  it('URLs de descarga: pcap de sesión y filtrado', () => {
    expect(api.sessionPcapUrl(5)).toBe('/api/sessions/5/pcap')
    expect(api.sessionPcapUrl('a/b c')).toBe('/api/sessions/a%2Fb%20c/pcap')
    expect(api.filteredPcapUrl({})).toBe('/api/pcap')
    expect(api.filteredPcapUrl({ ip: '192.168.1.20' })).toBe(
      '/api/pcap?ip=192.168.1.20'
    )
    expect(api.filteredPcapUrl({ protocol: 'TCP', ip: '', port: 0 })).toBe(
      '/api/pcap?protocol=TCP&port=0'
    )
    expect(api.filteredPcapUrl({ ip: 'a&b=c' })).toBe('/api/pcap?ip=a%26b%3Dc')
  })
  it('hosts, graph y httpOverview son GET sobre sus rutas', async () => {
    expect((await call(api.hosts()))[0]).toBe('/api/hosts')
    expect((await call(api.hostsByMac()))[0]).toBe('/api/hosts/by-mac')
    expect((await call(api.graph()))[0]).toBe('/api/graph')
    expect((await call(api.httpOverview()))[0]).toBe('/api/http')
  })
  it('dns omite q si no hay y la codifica si la hay', async () => {
    expect((await call(api.dns(undefined)))[0]).toBe('/api/dns')
    expect((await call(api.dns('')))[0]).toBe('/api/dns')
    expect((await call(api.dns('a b&c')))[0]).toBe('/api/dns?q=a+b%26c')
  })
  it('explain, sessionHttp y sessionTls codifican el id', async () => {
    expect((await call(api.explain('a/b')))[0]).toBe(
      '/api/sessions/a%2Fb/explain'
    )
    expect((await call(api.sessionHttp(3)))[0]).toBe('/api/sessions/3/http')
    expect((await call(api.sessionTls(3)))[0]).toBe('/api/sessions/3/tls')
  })
  it('caseTimeline y remoteAccess llevan sus filtros', async () => {
    expect((await call(api.caseTimeline('10.0.0.1')))[0]).toBe(
      '/api/case-timeline?host=10.0.0.1'
    )
    expect((await call(api.remoteAccess('SSH')))[0]).toBe(
      '/api/remote-access?service=SSH'
    )
  })
  it('httpBodyUrl codifica sesión e índice', () => {
    expect(api.httpBodyUrl(3, 0)).toBe('/api/sessions/3/http/0/body')
    expect(api.httpBodyUrl('a/b', '1 2')).toBe(
      '/api/sessions/a%2Fb/http/1%202/body'
    )
  })
  it('las funciones del Sistema piden solo con GET y a sus rutas', async () => {
    const calls: Array<[() => Promise<unknown>, string]> = [
      [() => api.systemOverview(), '/api/system/overview'],
      [() => api.systemPorts(), '/api/system/ports'],
      [() => api.systemConnections(), '/api/system/connections'],
      [() => api.systemServices(), '/api/system/services'],
      [() => api.systemStartup(), '/api/system/startup'],
    ]
    for (const [p, path] of calls) {
      const [url, opts] = await call(p())
      expect([url, opts.method]).toEqual([path, 'GET'])
    }
  })
  it('systemProcesses arma la query con orden y límite', async () => {
    const [url, opts] = await call(
      api.systemProcesses({ sort: 'cpu', limit: 600 })
    )
    expect(url).toBe('/api/system/processes?sort=cpu&limit=600')
    expect(opts.method).toBe('GET')
    expect((await call(api.systemProcesses({})))[0]).toBe(
      '/api/system/processes'
    )
  })
  it('systemProcess y systemProcessFile codifican el PID', async () => {
    expect((await call(api.systemProcess(42)))[0]).toBe(
      '/api/system/processes/42'
    )
    const [url, opts] = await call(api.systemProcessFile('4/../2'))
    expect(url).toBe('/api/system/processes/4%2F..%2F2/file')
    expect(opts.method).toBe('GET')
  })
  it('no existe ninguna función del Sistema que modifique (kill, terminate, disable...)', () => {
    const names = Object.keys(api).filter((k) => k.startsWith('system'))
    expect(names.length).toBe(8)
    for (const n of names) {
      expect(n.slice('system'.length)).not.toMatch(
        /^(Kill|Terminate|Stop|Suspend|Resume|Disable|Enable|Delete|Remove|Set|Close|Restart)/
      )
    }
  })
  it('exportUrl con y sin filtros', () => {
    expect(api.exportUrl({})).toBe('/api/export')
    expect(api.exportUrl(undefined)).toBe('/api/export')
    expect(api.exportUrl({ protocol: 'TCP', ip: '10.0.0.1', port: '80' })).toBe(
      '/api/export?protocol=TCP&ip=10.0.0.1&port=80'
    )
  })
})

describe('Soporte de red -> Red (api.support*)', () => {
  beforeEach(() => respondWith({}))

  it.each([
    ['supportConfig', '/api/support/config'],
    ['supportConfigRaw', '/api/support/config/raw'],
    ['supportWifi', '/api/support/wifi'],
    ['supportWifiHistory', '/api/support/wifi/history'],
    ['monitorStatus', '/api/support/monitor'],
  ] as const)('%s es GET a la URL correcta', async (name, url) => {
    const [u, o] = await call(api[name]())
    expect([u, o.method]).toEqual([url, 'GET'])
  })

  // Los sondeos que mandan tráfico a la red son POST: un GET ajeno sin Origin los dispararía.
  it.each([
    ['supportInternet', [], '/api/support/internet'],
    [
      'supportLatency',
      [{ host: '8.8.8.8', port: 443, samples: 8 }],
      '/api/support/latency?host=8.8.8.8&port=443&samples=8',
    ],
    ['supportPing', ['1.1.1.1', 4], '/api/support/ping?host=1.1.1.1&count=4'],
    [
      'supportTraceroute',
      ['www.google.com'],
      '/api/support/traceroute?host=www.google.com',
    ],
    [
      'supportPorts',
      ['10.0.0.2', '22,80'],
      '/api/support/ports?host=10.0.0.2&ports=22%2C80',
    ],
    [
      'supportRdp',
      ['10.0.0.2', 3389],
      '/api/support/rdp?host=10.0.0.2&port=3389',
    ],
    ['supportTime', ['pool.ntp.org'], '/api/support/time?server=pool.ntp.org'],
    ['supportDevices', [false], '/api/support/devices'],
    ['supportDevices', [true], '/api/support/devices?scan=true'],
    ['supportDuplicateIp', [], '/api/support/duplicate-ip'],
  ] as const)('%s es POST a la URL correcta', async (name, args, url) => {
    const fn = api[name] as (...a: unknown[]) => Promise<unknown>
    const [u, o] = await call(fn(...args))
    expect([u, o.method]).toEqual([url, 'POST'])
  })

  it('un host con caracteres raros va codificado en la query', async () => {
    expect((await call(api.supportPing('a;b c&d', 1)))[0]).toBe(
      '/api/support/ping?host=a%3Bb+c%26d&count=1'
    )
  })

  it('monitorStart/Stop/Clear son POST', async () => {
    let [u, o] = await call(api.monitorStart(5))
    expect([u, o.method]).toEqual([
      '/api/support/monitor/start?interval=5',
      'POST',
    ])
    ;[u, o] = await call(api.monitorStop())
    expect([u, o.method]).toEqual(['/api/support/monitor/stop', 'POST'])
    ;[u, o] = await call(api.monitorClear())
    expect([u, o.method]).toEqual(['/api/support/monitor/clear', 'POST'])
  })

  it('las lecturas pasan la signal', async () => {
    const ctl = new AbortController()
    const [, o] = await call(api.supportWifi(ctl.signal))
    expect(o.signal).toBe(ctl.signal)
  })
})

describe('ticketUrl (descargas con token)', () => {
  beforeEach(() => respondWith({ ticket: 'a b', query: 'ticket' }))

  it('pide el ticket de la ruta SIN query y lo agrega a la URL', async () => {
    const url = await api.ticketUrl('/api/export?ip=1.2.3.4')
    const [path, opts] = last()
    expect(path).toBe('/api/download-ticket')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body as string)).toEqual({ path: '/api/export' })
    expect(url).toBe('/api/export?ip=1.2.3.4&ticket=a%20b')
  })

  it('sin query usa ? y no deja el token en la URL', async () => {
    expect(await api.ticketUrl('/api/report')).toBe('/api/report?ticket=a%20b')
  })
})

describe('triaje, reglas e IOC', () => {
  beforeEach(() => respondWith({}))

  it('saveNote: PUT /api/sessions/{id}/note con el cuerpo', async () => {
    const [url, opts] = await call(
      api.saveNote(7, { note: 'hola', reviewed: true })
    )
    expect(url).toBe('/api/sessions/7/note')
    expect(opts.method).toBe('PUT')
    expect(JSON.parse(opts.body as string)).toEqual({
      note: 'hola',
      reviewed: true,
    })
    expect(opts.headers).toEqual({ 'Content-Type': 'application/json' })
  })
  it('saveNote codifica el id y manda el texto hostil solo como JSON', async () => {
    const hostil = '"><script>alert(1)</script>'
    const [url, opts] = await call(
      api.saveNote('a/b?c', { note: hostil, reviewed: false })
    )
    expect(url).toBe('/api/sessions/a%2Fb%3Fc/note')
    expect(JSON.parse(opts.body as string).note).toBe(hostil)
  })
  it('iocs GET con señal; loadIocs POST {path}; clearIocs DELETE', async () => {
    const ctl = new AbortController()
    let [url, opts] = await call(api.iocs(ctl.signal))
    expect([url, opts.method, opts.signal]).toEqual([
      '/api/iocs',
      'GET',
      ctl.signal,
    ])
    ;[url, opts] = await call(api.loadIocs('C:\\listas\\feed.txt'))
    expect([url, opts.method]).toEqual(['/api/iocs', 'POST'])
    expect(JSON.parse(opts.body as string)).toEqual({
      path: 'C:\\listas\\feed.txt',
    })
    ;[url, opts] = await call(api.clearIocs())
    expect([url, opts.method]).toEqual(['/api/iocs', 'DELETE'])
  })
  it('rules, previewRule y saveRule', async () => {
    expect((await call(api.rules()))[0]).toBe('/api/rules')
    let [url, opts] = await call(
      api.previewRule({ name: 'x', severity: 'low' })
    )
    expect([url, opts.method]).toEqual(['/api/rules/preview', 'POST'])
    ;[url, opts] = await call(api.saveRule({ name: 'x' }))
    expect([url, opts.method]).toEqual(['/api/rules', 'POST'])
  })
})
