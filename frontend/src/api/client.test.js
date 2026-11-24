import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api, ApiError, buildQuery, normalizeDetail } from "./client.js";

const resp = (status, body, { statusText = "", json = true } = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText,
  json: json
    ? async () => body
    : async () => {
        throw new SyntaxError("no json");
      },
});

let fetchMock;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("normalizeDetail", () => {
  it("string tal cual", () => expect(normalizeDetail("hola")).toBe("hola"));
  it("null/undefined -> null", () => {
    expect(normalizeDetail(null)).toBeNull();
    expect(normalizeDetail(undefined)).toBeNull();
  });
  it("lista de validación con loc (quita query/body)", () => {
    expect(normalizeDetail([{ loc: ["query", "port"], msg: "fuera de rango" }])).toBe("port: fuera de rango");
    expect(
      normalizeDetail([
        { loc: ["body", "path"], msg: "requerido" },
        { loc: ["query", "ip"], msg: "inválida" },
      ]),
    ).toBe("path: requerido; ip: inválida");
  });
  it("elemento sin loc usa solo msg; sin msg serializa", () => {
    expect(normalizeDetail([{ msg: "x" }])).toBe("x");
    expect(normalizeDetail([{ loc: [] }])).toBe('{"loc":[]}');
  });
  it("objeto -> JSON", () => expect(normalizeDetail({ a: 1 })).toBe('{"a":1}'));
  it("lista vacía -> cadena vacía", () => expect(normalizeDetail([])).toBe(""));
});

describe("buildQuery", () => {
  it("vacío -> ''", () => {
    expect(buildQuery()).toBe("");
    expect(buildQuery({})).toBe("");
    expect(buildQuery({ a: null, b: undefined, c: "" })).toBe("");
  });
  it("omite vacíos pero conserva 0 y false", () => {
    expect(buildQuery({ a: 0, b: false, c: "", d: null, e: "x" })).toBe("?a=0&b=false&e=x");
  });
  it("escapa caracteres especiales y unicode", () => {
    const q = buildQuery({ q: "a b&c=d/é#" });
    expect(q).toBe("?q=a+b%26c%3Dd%2F%C3%A9%23");
    expect(new URLSearchParams(q).get("q")).toBe("a b&c=d/é#");
  });
});

describe("request via api.*", () => {
  it("éxito devuelve el JSON", async () => {
    fetchMock.mockResolvedValue(resp(200, [{ a: 1 }]));
    await expect(api.alerts()).resolves.toEqual([{ a: 1 }]);
  });

  it.each([404, 409, 422, 500])("error %i con JSON string", async (st) => {
    fetchMock.mockResolvedValue(resp(st, { detail: "algo falló" }));
    const err = await api.capture().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(st);
    expect(err.message).toBe("algo falló");
    expect(err.detail).toBe("algo falló");
  });

  it("422 con lista de validación", async () => {
    fetchMock.mockResolvedValue(resp(422, { detail: [{ loc: ["query", "port"], msg: "inválido" }] }));
    const err = await api.sessions({ port: 99999 }).catch((e) => e);
    expect(err.message).toBe("port: inválido");
  });

  it("cuerpo no JSON usa statusText", async () => {
    fetchMock.mockResolvedValue(resp(502, null, { statusText: "Bad Gateway", json: false }));
    const err = await api.capture().catch((e) => e);
    expect(err.status).toBe(502);
    expect(err.message).toBe("Bad Gateway");
  });

  it("sin statusText ni JSON -> 'Error N'", async () => {
    fetchMock.mockResolvedValue(resp(500, null, { statusText: "", json: false }));
    const err = await api.capture().catch((e) => e);
    expect(err.message).toBe("Error 500");
  });

  it("JSON sin detail usa statusText", async () => {
    fetchMock.mockResolvedValue(resp(500, {}, { statusText: "Internal Server Error" }));
    const err = await api.capture().catch((e) => e);
    expect(err.message).toBe("Internal Server Error");
  });

  it("fallo de red -> ApiError status 0 legible", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const err = await api.capture().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/No se pudo conectar/);
  });

  it("AbortError se propaga sin envolver", async () => {
    const abort = new DOMException("abortado", "AbortError");
    fetchMock.mockRejectedValue(abort);
    const err = await api.capture().catch((e) => e);
    expect(err).toBe(abort);
    expect(err).not.toBeInstanceOf(ApiError);
  });

  it("pasa la señal a fetch", async () => {
    fetchMock.mockResolvedValue(resp(200, {}));
    const ctl = new AbortController();
    await api.capture(ctl.signal);
    expect(fetchMock.mock.calls[0][1].signal).toBe(ctl.signal);
  });
});

describe("métodos, URLs y cuerpos", () => {
  beforeEach(() => fetchMock.mockResolvedValue(resp(200, {})));
  const last = () => fetchMock.mock.calls.at(-1);

  it("analyze: POST /api/analyze con {path} y Content-Type", async () => {
    await api.analyze("C:\\caps\\a.pcap");
    const [url, opts] = last();
    expect(url).toBe("/api/analyze");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ path: "C:\\caps\\a.pcap" });
    expect(opts.headers).toEqual({ "Content-Type": "application/json" });
  });
  it("demo: POST sin cuerpo", async () => {
    await api.demo();
    const [url, opts] = last();
    expect(url).toBe("/api/demo");
    expect(opts.method).toBe("POST");
    expect(opts.body).toBeUndefined();
    expect(opts.headers).toBeUndefined();
  });
  it("capture/interfaces/liveStatus son GET", async () => {
    await api.capture();
    expect([last()[0], last()[1].method]).toEqual(["/api/capture", "GET"]);
    await api.interfaces();
    expect([last()[0], last()[1].method]).toEqual(["/api/interfaces", "GET"]);
    await api.liveStatus();
    expect([last()[0], last()[1].method]).toEqual(["/api/live/status", "GET"]);
  });
  it("liveStart POST con cuerpo; liveStop POST", async () => {
    await api.liveStart({ interface: "eth0" });
    expect(last()[0]).toBe("/api/live/start");
    expect(JSON.parse(last()[1].body)).toEqual({ interface: "eth0" });
    await api.liveStop();
    expect([last()[0], last()[1].method]).toEqual(["/api/live/stop", "POST"]);
  });
  it("sessions arma la query omitiendo vacíos y conservando 0", async () => {
    await api.sessions({ protocol: "TCP", ip: "", port: 0, limit: 25, offset: 0 });
    expect(last()[0]).toBe("/api/sessions?protocol=TCP&port=0&limit=25&offset=0");
  });
  it("alerts con y sin severidad", async () => {
    await api.alerts("high");
    expect(last()[0]).toBe("/api/alerts?severity=high");
    await api.alerts(undefined);
    expect(last()[0]).toBe("/api/alerts");
  });
  it("sessionPackets y packet codifican el id", async () => {
    await api.sessionPackets("a/b c?", { limit: 50, offset: 0 });
    expect(last()[0]).toBe("/api/sessions/a%2Fb%20c%3F/packets?limit=50&offset=0");
    await api.packet("1/../2");
    expect(last()[0]).toBe("/api/packets/1%2F..%2F2");
    await api.packet(7);
    expect(last()[0]).toBe("/api/packets/7");
  });
  it("stream codifica el id, usa GET y pasa la señal", async () => {
    const ctl = new AbortController();
    await api.stream("a/b c?", ctl.signal);
    expect(last()[0]).toBe("/api/sessions/a%2Fb%20c%3F/stream");
    expect(last()[1].signal).toBe(ctl.signal);
    expect(last()[1].method ?? "GET").toBe("GET");
    await api.stream(7);
    expect(last()[0]).toBe("/api/sessions/7/stream");
  });
  it("stream propaga el mensaje de error del servidor", async () => {
    fetchMock.mockResolvedValueOnce(resp(422, { detail: "solo las sesiones TCP" }));
    await expect(api.stream(1)).rejects.toMatchObject({ status: 422, message: "solo las sesiones TCP" });
  });
  it("closeCapture hace DELETE /api/capture", async () => {
    fetchMock.mockResolvedValueOnce(resp(200, { cleared: true }));
    await expect(api.closeCapture()).resolves.toEqual({ cleared: true });
    expect([last()[0], last()[1].method]).toEqual(["/api/capture", "DELETE"]);
  });
  it("sessionPcapUrl codifica el id y filteredPcapUrl arma la query omitiendo vacíos", () => {
    expect(api.sessionPcapUrl(5)).toBe("/api/sessions/5/pcap");
    expect(api.sessionPcapUrl("a/b c")).toBe("/api/sessions/a%2Fb%20c/pcap");
    expect(api.filteredPcapUrl({})).toBe("/api/pcap");
    expect(api.filteredPcapUrl({ ip: "192.168.1.20" })).toBe("/api/pcap?ip=192.168.1.20");
    expect(api.filteredPcapUrl({ protocol: "TCP", ip: "", port: 0 })).toBe("/api/pcap?protocol=TCP&port=0");
    expect(api.filteredPcapUrl({ ip: "a&b=c" })).toBe("/api/pcap?ip=a%26b%3Dc");
  });
  it("hosts, graph, httpOverview y closeCapture son GET/DELETE sobre sus rutas", async () => {
    await api.hosts();
    expect([last()[0], last()[1].method]).toEqual(["/api/hosts", "GET"]);
    await api.graph();
    expect([last()[0], last()[1].method]).toEqual(["/api/graph", "GET"]);
    await api.httpOverview();
    expect([last()[0], last()[1].method]).toEqual(["/api/http", "GET"]);
  });
  it("dns omite q si no hay y la codifica si la hay", async () => {
    await api.dns(undefined);
    expect(last()[0]).toBe("/api/dns");
    await api.dns("");
    expect(last()[0]).toBe("/api/dns");
    await api.dns("a b&c");
    expect(last()[0]).toBe("/api/dns?q=a+b%26c");
  });
  it("explain, sessionHttp y sessionTls codifican el id", async () => {
    await api.explain("a/b");
    expect(last()[0]).toBe("/api/sessions/a%2Fb/explain");
    await api.sessionHttp(3);
    expect(last()[0]).toBe("/api/sessions/3/http");
    await api.sessionTls(3);
    expect(last()[0]).toBe("/api/sessions/3/tls");
  });
  it("httpBodyUrl codifica sesión e índice", () => {
    expect(api.httpBodyUrl(3, 0)).toBe("/api/sessions/3/http/0/body");
    expect(api.httpBodyUrl("a/b", "1 2")).toBe("/api/sessions/a%2Fb/http/1%202/body");
  });
  it("las funciones del Sistema piden solo con GET y a sus rutas", async () => {
    await api.systemOverview();
    expect([last()[0], last()[1].method]).toEqual(["/api/system/overview", "GET"]);
    await api.systemPorts();
    expect([last()[0], last()[1].method]).toEqual(["/api/system/ports", "GET"]);
    await api.systemConnections();
    expect([last()[0], last()[1].method]).toEqual(["/api/system/connections", "GET"]);
    await api.systemServices();
    expect([last()[0], last()[1].method]).toEqual(["/api/system/services", "GET"]);
    await api.systemStartup();
    expect([last()[0], last()[1].method]).toEqual(["/api/system/startup", "GET"]);
  });
  it("systemProcesses arma la query con orden y límite", async () => {
    await api.systemProcesses({ sort: "cpu", limit: 600 });
    expect(last()[0]).toBe("/api/system/processes?sort=cpu&limit=600");
    expect(last()[1].method).toBe("GET");
    await api.systemProcesses({});
    expect(last()[0]).toBe("/api/system/processes");
  });
  it("systemProcess y systemProcessFile codifican el PID", async () => {
    await api.systemProcess(42);
    expect(last()[0]).toBe("/api/system/processes/42");
    await api.systemProcessFile("4/../2");
    expect(last()[0]).toBe("/api/system/processes/4%2F..%2F2/file");
    expect(last()[1].method).toBe("GET");
  });
  it("no existe ninguna función del Sistema que modifique (kill, terminate, disable...)", () => {
    const names = Object.keys(api).filter((k) => k.startsWith("system"));
    expect(names.length).toBe(8);
    for (const n of names) expect(n.slice("system".length)).not.toMatch(/^(Kill|Terminate|Stop|Suspend|Resume|Disable|Enable|Delete|Remove|Set|Close|Restart)/);
  });
  it("exportUrl con y sin filtros", () => {
    expect(api.exportUrl({})).toBe("/api/export");
    expect(api.exportUrl(undefined)).toBe("/api/export");
    expect(api.exportUrl({ protocol: "TCP", ip: "10.0.0.1", port: "80" })).toBe(
      "/api/export?protocol=TCP&ip=10.0.0.1&port=80",
    );
  });
});

describe("Soporte de red → Red (api.support*)", () => {
  beforeEach(() => fetchMock.mockResolvedValue(resp(200, {})));
  const last = () => fetchMock.mock.calls.at(-1);

  it.each([
    ["supportConfig", [], "/api/support/config"],
    ["supportConfigRaw", [], "/api/support/config/raw"],
    ["supportWifi", [], "/api/support/wifi"],
    ["supportWifiHistory", [], "/api/support/wifi/history"],
    ["monitorStatus", [], "/api/support/monitor"],
  ])("%s es GET a la URL correcta", async (name, args, url) => {
    await api[name](...args);
    expect([last()[0], last()[1].method]).toEqual([url, "GET"]);
  });

  // Los sondeos que mandan tráfico a la red son POST: un GET ajeno sin Origin los dispararía.
  it.each([
    ["supportInternet", [], "/api/support/internet"],
    ["supportLatency", [{ host: "8.8.8.8", port: 443, samples: 8 }], "/api/support/latency?host=8.8.8.8&port=443&samples=8"],
    ["supportPing", ["1.1.1.1", 4], "/api/support/ping?host=1.1.1.1&count=4"],
    ["supportTraceroute", ["www.google.com"], "/api/support/traceroute?host=www.google.com"],
    ["supportPorts", ["10.0.0.2", "22,80"], "/api/support/ports?host=10.0.0.2&ports=22%2C80"],
    ["supportRdp", ["10.0.0.2", 3389], "/api/support/rdp?host=10.0.0.2&port=3389"],
    ["supportTime", ["pool.ntp.org"], "/api/support/time?server=pool.ntp.org"],
    ["supportDevices", [false], "/api/support/devices"],
    ["supportDevices", [true], "/api/support/devices?scan=true"],
    ["supportDuplicateIp", [], "/api/support/duplicate-ip"],
  ])("%s es POST a la URL correcta", async (name, args, url) => {
    await api[name](...args);
    expect([last()[0], last()[1].method]).toEqual([url, "POST"]);
  });

  it("un host con caracteres raros va codificado en la query", async () => {
    await api.supportPing("a;b c&d", 1);
    expect(last()[0]).toBe("/api/support/ping?host=a%3Bb+c%26d&count=1");
  });

  it("monitorStart/Stop/Clear son POST", async () => {
    await api.monitorStart(5);
    expect([last()[0], last()[1].method]).toEqual(["/api/support/monitor/start?interval=5", "POST"]);
    await api.monitorStop();
    expect([last()[0], last()[1].method]).toEqual(["/api/support/monitor/stop", "POST"]);
    await api.monitorClear();
    expect([last()[0], last()[1].method]).toEqual(["/api/support/monitor/clear", "POST"]);
  });

  it("las lecturas pasan la signal", async () => {
    const ctl = new AbortController();
    await api.supportWifi(ctl.signal);
    expect(last()[1].signal).toBe(ctl.signal);
  });
});

describe("ticketUrl (descargas con token)", () => {
  beforeEach(() => fetchMock.mockResolvedValue(resp(200, { ticket: "a b", query: "ticket" })));

  it("pide el ticket de la ruta SIN query y lo agrega a la URL", async () => {
    const url = await api.ticketUrl("/api/export?ip=1.2.3.4");
    const [path, opts] = fetchMock.mock.calls.at(-1);
    expect(path).toBe("/api/download-ticket");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ path: "/api/export" });
    expect(url).toBe("/api/export?ip=1.2.3.4&ticket=a%20b");
  });

  it("sin query usa ? y no deja el token en la URL", async () => {
    expect(await api.ticketUrl("/api/report")).toBe("/api/report?ticket=a%20b");
  });
});
