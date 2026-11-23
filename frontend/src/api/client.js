// Cliente de la API. Un único lugar que conoce las URLs y cómo se traducen los
// errores: los componentes nunca llaman a fetch directamente.

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail);
    this.name = "ApiError";
    this.status = status; // 0 = no se pudo conectar
    this.detail = detail;
  }
}

// FastAPI responde `detail` como texto (nuestros errores) o como lista (errores
// de validación de parámetros). Lo normalizamos a un solo texto legible.
export function normalizeDetail(detail) {
  if (detail == null) return null;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        const where = Array.isArray(d.loc) ? d.loc.filter((p) => p !== "query" && p !== "body").join(".") : "";
        const msg = d.msg ?? JSON.stringify(d);
        return where ? `${where}: ${msg}` : msg;
      })
      .join("; ");
  }
  return JSON.stringify(detail);
}

// Arma "?a=1&b=2" omitiendo valores vacíos (null, undefined, ""), así un filtro
// sin usar no viaja como "ip=" (que el servidor rechazaría por inválido).
export function buildQuery(params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === "") continue;
    q.append(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

async function request(path, { method = "GET", body, signal } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (e) {
    if (e?.name === "AbortError") throw e;
    throw new ApiError(0, "No se pudo conectar con la API. ¿Está en marcha?");
  }
  if (!res.ok) {
    let detail = res.statusText || `Error ${res.status}`;
    try {
      const j = await res.json();
      detail = normalizeDetail(j?.detail) ?? detail;
    } catch {
      /* cuerpo no JSON: nos quedamos con el statusText */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json();
}

export const api = {
  demo: () => request("/api/demo", { method: "POST" }),
  analyze: (path) => request("/api/analyze", { method: "POST", body: { path } }),
  capture: (signal) => request("/api/capture", { signal }),
  closeCapture: () => request("/api/capture", { method: "DELETE" }),
  sessions: (params, signal) => request(`/api/sessions${buildQuery(params)}`, { signal }),
  timeline: (signal) => request("/api/timeline", { signal }),
  // Entender la captura: equipos y grafo, DNS, HTTP, y la explicación en palabras simples de una sesión.
  hosts: (signal) => request("/api/hosts", { signal }),
  hostsByMac: (signal) => request("/api/hosts/by-mac", { signal }),
  graph: (signal) => request("/api/graph", { signal }),
  dns: (q, signal) => request(`/api/dns${buildQuery({ q })}`, { signal }),
  explain: (id, signal) => request(`/api/sessions/${encodeURIComponent(id)}/explain`, { signal }),
  sessionHttp: (id, signal) => request(`/api/sessions/${encodeURIComponent(id)}/http`, { signal }),
  sessionTls: (id, signal) => request(`/api/sessions/${encodeURIComponent(id)}/tls`, { signal }),
  httpOverview: (signal) => request("/api/http", { signal }),
  httpBodyUrl: (id, index) => `/api/sessions/${encodeURIComponent(id)}/http/${encodeURIComponent(index)}/body`,
  caseTimeline: (host, signal) => request(`/api/case-timeline${buildQuery({ host })}`, { signal }),
  remoteAccess: (service, signal) => request(`/api/remote-access${buildQuery({ service })}`, { signal }),
  alerts: (severity, signal) => request(`/api/alerts${buildQuery({ severity })}`, { signal }),
  sessionPackets: (id, params, signal) =>
    request(`/api/sessions/${encodeURIComponent(id)}/packets${buildQuery(params)}`, { signal }),
  stream: (id, signal) => request(`/api/sessions/${encodeURIComponent(id)}/stream`, { signal }),
  packet: (index, signal) => request(`/api/packets/${encodeURIComponent(index)}`, { signal }),
  interfaces: () => request("/api/interfaces"),
  liveStart: (body) => request("/api/live/start", { method: "POST", body }),
  liveStatus: (signal) => request("/api/live/status", { signal }),
  liveStop: () => request("/api/live/stop", { method: "POST" }),
  // La exportación y el informe son descargas: devolvemos la URL para un <a download>.
  exportUrl: (filters) => `/api/export${buildQuery(filters)}`,
  reportUrl: () => "/api/report",
  // Descargas de .pcap: SOLO los paquetes de una sesión, o de las sesiones que cumplen los filtros.
  sessionPcapUrl: (id) => `/api/sessions/${encodeURIComponent(id)}/pcap`,
  filteredPcapUrl: (filters) => `/api/pcap${buildQuery(filters)}`,
  // Triaje: nota/marca "revisada" por sesión y lista de indicadores de compromiso (IOC).
  saveNote: (id, body) => request(`/api/sessions/${encodeURIComponent(id)}/note`, { method: "PUT", body }),
  rules: (signal) => request("/api/rules", { signal }),
  previewRule: (body, signal) => request("/api/rules/preview", { method: "POST", body, signal }),
  saveRule: (body) => request("/api/rules", { method: "POST", body }),
  iocs: (signal) => request("/api/iocs", { signal }),
  loadIocs: (path) => request("/api/iocs", { method: "POST", body: { path } }),
  clearIocs: () => request("/api/iocs", { method: "DELETE" }),
  // Soporte de red → Sistema: todo de SOLO LECTURA sobre el equipo donde corre Tracewell.
  systemOverview: (signal) => request("/api/system/overview", { signal }),
  systemProcesses: (params, signal) => request(`/api/system/processes${buildQuery(params)}`, { signal }),
  systemProcess: (pid, signal) => request(`/api/system/processes/${encodeURIComponent(pid)}`, { signal }),
  systemProcessFile: (pid, signal) => request(`/api/system/processes/${encodeURIComponent(pid)}/file`, { signal }),
  systemPorts: (signal) => request("/api/system/ports", { signal }),
  systemConnections: (signal) => request("/api/system/connections", { signal }),
  systemServices: (signal) => request("/api/system/services", { signal }),
  systemStartup: (signal) => request("/api/system/startup", { signal }),
  // Soporte de red → Red: pruebas de solo lectura. Las que salen a la red las pide la persona a propósito.
  supportConfig: (signal) => request("/api/support/config", { signal }),
  supportConfigRaw: (signal) => request("/api/support/config/raw", { signal }),
  supportInternet: (signal) => request("/api/support/internet", { signal }),
  supportLatency: (params, signal) => request(`/api/support/latency${buildQuery(params)}`, { signal }),
  supportPing: (host, count, signal) => request(`/api/support/ping${buildQuery({ host, count })}`, { signal }),
  supportTraceroute: (host, signal) => request(`/api/support/traceroute${buildQuery({ host })}`, { signal }),
  supportPorts: (host, ports, signal) => request(`/api/support/ports${buildQuery({ host, ports })}`, { signal }),
  supportRdp: (host, port, signal) => request(`/api/support/rdp${buildQuery({ host, port })}`, { signal }),
  supportTime: (server, signal) => request(`/api/support/time${buildQuery({ server })}`, { signal }),
  supportDevices: (scan, signal) => request(`/api/support/devices${buildQuery({ scan: scan ? "true" : "" })}`, { signal }),
  supportWifi: (signal) => request("/api/support/wifi", { signal }),
  supportWifiHistory: (signal) => request("/api/support/wifi/history", { signal }),
  supportDuplicateIp: (signal) => request("/api/support/duplicate-ip", { signal }),
  monitorStatus: (signal) => request("/api/support/monitor", { signal }),
  monitorStart: (interval) => request(`/api/support/monitor/start${buildQuery({ interval })}`, { method: "POST" }),
  monitorStop: () => request("/api/support/monitor/stop", { method: "POST" }),
  monitorClear: () => request("/api/support/monitor/clear", { method: "POST" }),
};
