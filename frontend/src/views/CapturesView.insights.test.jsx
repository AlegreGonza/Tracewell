import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api/client.js", () => ({
  api: {
    demo: vi.fn(), analyze: vi.fn(), capture: vi.fn(), sessions: vi.fn(), alerts: vi.fn(), timeline: vi.fn(),
    sessionPackets: vi.fn(), packet: vi.fn(), stream: vi.fn(), interfaces: vi.fn(), liveStart: vi.fn(),
    liveStatus: vi.fn(), liveStop: vi.fn(), exportUrl: vi.fn(() => "/api/export"), closeCapture: vi.fn(),
    iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn(), saveNote: vi.fn(), reportUrl: vi.fn(() => "/api/report"),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`), filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`),
    hosts: vi.fn(), graph: vi.fn(), dns: vi.fn(), explain: vi.fn(), sessionHttp: vi.fn(), sessionTls: vi.fn(), hostsByMac: vi.fn(() => Promise.resolve({ total: 0, items: [] })), caseTimeline: vi.fn(() => Promise.resolve({ host: null, total: 0, truncated: false, items: [] })), remoteAccess: vi.fn(() => Promise.resolve({ total: 0, services: [] })), httpOverview: vi.fn(),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
  },
}));
import { api } from "../api/client.js";
import App from "./CapturesView.jsx";
import { STEPS } from "../components/captures/GuidedCase.jsx";

const summary = (source) => ({
  source, format: "pcap", linktype: 1, snaplen: 65535, alerts: 1, rules: 8,
  stats: { sessions: 2, packets: 5, bytes: 500, by_protocol: {}, non_ip: 0, malformed: 0 },
});
const alertOf = {
  rule_id: "port_scan", name: "Escaneo de puertos", severity: "high", mitre_technique: "T1046", mitre_name: "Scan", mitre_tactic: "Discovery",
  description: "d", src_ip: "192.168.1.66", dst_ip: "192.168.1.5", first_ts: 1700000000, evidence: {},
};
const sess = (id, ip = "192.168.1.66") => ({
  id, protocol: "TCP", src_ip: ip, src_port: 1000 + id, dst_ip: "192.168.1.5", dst_port: 21, packets: 3, bytes: 300, first_ts: 1, last_ts: 2, duration: 1,
});
const host = (ip, over = {}) => ({
  ip, kind: "interna", sessions: 1, packets: 1, bytes: 100, initiated: 1, received: 0, peers: 1, protocols: ["TCP"], services: [], name: null,
  alerts: 0, alert_rules: [], ioc: [], ...over,
});
const dnsRow = { name: "x.evil-c2.example", qtype: "A", queries: 1, responses: 0, rcodes: {}, answers: [], clients: [], first_ts: 1, last_ts: 2, min_ttl: null, hints: ["h"] };
const httpItem = {
  index: 0, session_id: 3, src: "192.168.1.10:51000", dst: "93.184.216.34:80", method: "GET", target: "/", host: "www.example.com", status: 200,
  response_type: "text/html", response_bytes: 5, sensitive_fields: [], auth: null, location: null, complete: true, file: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  api.capture.mockResolvedValue(summary("demo.pcap"));
  api.alerts.mockResolvedValue([alertOf]);
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
  api.timeline.mockResolvedValue({ start: 1700000000, bucket_seconds: 1, packets: [1, 2], bytes: [1, 2] });
  api.sessions.mockResolvedValue({ total: 2, items: [sess(1), sess(2, "192.168.1.20")] });
  api.sessionPackets.mockResolvedValue({ items: [], has_more: false });
  api.hosts.mockResolvedValue({ total: 2, items: [host("192.168.1.66", { alerts: 1 }), host("192.168.1.5")] });
  api.graph.mockResolvedValue({
    nodes: [{ ip: "192.168.1.66", kind: "interna", label: "192.168.1.66", bytes: 100, sessions: 1, alerts: 1, ioc: false },
      { ip: "93.184.216.34", kind: "publica", label: "www.example.com", bytes: 100, sessions: 1, alerts: 0, ioc: false }],
    edges: [], truncated: false,
  });
  api.dns.mockResolvedValue({ summary: { names: 1, queries: 1, responses: 0, nxdomain: 0, flagged: 1, dropped: 0 }, items: [dnsRow] });
  api.httpOverview.mockResolvedValue({ scanned: 1, capped: false, items: [httpItem] });
  api.explain.mockResolvedValue({ protocol: "TCP", outcome: "abierta", summary: ["Frase."], steps: [] });
  api.sessionHttp.mockResolvedValue({ exchanges: [], incomplete: false });
  api.sessionTls.mockResolvedValue({ tls: false });
  api.stream.mockResolvedValue({ chunks: [], origin_bytes: 0, destination_bytes: 0, encrypted: false, truncated: false });
  api.packet.mockResolvedValue({ index: 0, ts: 1, caplen: 1, origlen: 1, snaplen_limited: false, session_id: 1, endpoints: null, hexdump: "x" });
});

const follows = (a, b) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
const h2 = (name) => screen.getByRole("heading", { level: 2, name });

describe("App: orden de las tarjetas", () => {
  it("Resumen, Tráfico, Alertas, ATT&CK, Equipos, DNS, HTTP, IOC, Sesiones (con Puntaje de riesgo y el caso guiado tras el panorama)", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "DNS" });
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    await screen.findByRole("heading", { name: "Equipos" });
    const order = [
      h2("Resumen"), h2("Tráfico en el tiempo"), h2("Puntaje de riesgo"), h2(/Caso guiado/), h2("Alertas"), h2(/Mapa MITRE/), h2("Equipos"), h2("DNS"), h2("HTTP sin cifrar"),
      h2("Indicadores (IOC)"), h2("Sesiones"),
    ];
    for (let i = 0; i < order.length - 1; i++) expect(follows(order[i], order[i + 1]), `${i}`).toBe(true);
  });

  it("sin DNS ni HTTP en la captura esas tarjetas no aparecen y el resto sí", async () => {
    api.dns.mockResolvedValue({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] });
    api.httpOverview.mockResolvedValue({ scanned: 0, capped: false, items: [] });
    render(<App />);
    await screen.findByRole("heading", { name: "Equipos" });
    expect(screen.queryByRole("heading", { name: "DNS" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "HTTP sin cifrar" })).toBeNull();
    expect(h2("Sesiones")).toBeInTheDocument();
  });

  it("las tres vistas nuevas piden sus datos al cargar la captura", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Equipos" });
    expect(api.hosts).toHaveBeenCalled();
    expect(api.graph).toHaveBeenCalled();
    expect(api.dns).toHaveBeenCalledWith(undefined, expect.any(AbortSignal));
    expect(api.httpOverview).toHaveBeenCalled();
  });

  it("un error de una de las vistas se muestra en el banner global", async () => {
    api.httpOverview.mockRejectedValue(new Error("http roto"));
    render(<App />);
    expect(await screen.findByText(/http roto/)).toBeInTheDocument();
  });
});

describe("App: caso guiado del demo", () => {
  it("solo aparece con source demo.pcap", async () => {
    api.capture.mockResolvedValue(summary("otra.pcap"));
    render(<App />);
    await screen.findByRole("heading", { name: "Resumen" });
    expect(screen.queryByRole("heading", { name: /Caso guiado/ })).toBeNull();
  });

  it("con el demo aparece con sus 7 pasos", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: /Caso guiado/ })).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(7);
  });

  it("todo destino de salto de los pasos existe en la pantalla del demo montado", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "DNS" });
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    const targets = STEPS.filter((s) => s.action?.jump).map((s) => s.action.jump);
    expect(targets.sort()).toEqual(["alerts-title", "dns-title", "httpall-title", "summary-title"]);
    for (const id of targets) expect(document.getElementById(id), id).not.toBeNull();
  });

  it("el botón de salto hace scroll al título real", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "DNS" });
    const el = document.getElementById("dns-title");
    el.scrollIntoView = vi.fn();
    await userEvent.click(screen.getByRole("button", { name: "Ir a DNS" }));
    expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it("el botón con IP filtra la tabla de sesiones por esa IP (y limpia protocolo y puerto)", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Equipos" });
    await userEvent.click(screen.getByRole("button", { name: "Filtrar por 192.168.1.20" }));
    await waitFor(() => expect(api.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ ip: "192.168.1.20", protocol: "", port: "" }), expect.anything()));
    expect(screen.getByLabelText("IP")).toHaveValue("192.168.1.20");
  });

  it("al salir del demo desaparece", async () => {
    api.closeCapture.mockResolvedValue({ cleared: true });
    render(<App />);
    await screen.findByRole("heading", { name: /Caso guiado/ });
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: /Caso guiado/ })).toBeNull());
  });
});

describe("App: filtrar por IP desde equipos y HTTP", () => {
  it("clic en un nodo del grafo filtra por su IP y limpia la selección", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Equipos" });
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    expect(await screen.findByRole("heading", { name: "Sesión 1" })).toBeInTheDocument();
    const node = screen.getByRole("button", { name: /www\.example\.com \(93\.184\.216\.34\)/ });
    await userEvent.click(node);
    await waitFor(() => expect(api.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ ip: "93.184.216.34", protocol: "", port: "" }), expect.anything()));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Sesión 1" })).toBeNull());
  });

  it("clic en la IP de la tabla de equipos filtra", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Equipos" });
    const table = document.querySelector(".hosts-table");
    await userEvent.click(within(table).getByRole("button", { name: "192.168.1.5" }));
    await waitFor(() => expect(api.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ ip: "192.168.1.5" }), expect.anything()));
  });

  it("clic en el origen de una petición HTTP filtra por la IP sin el puerto", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    await userEvent.click(screen.getByRole("button", { name: "192.168.1.10:51000" }));
    await waitFor(() => expect(api.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ ip: "192.168.1.10" }), expect.anything()));
  });

  it("el scroll al título de Sesiones se intenta tras filtrar", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Equipos" });
    const title = document.getElementById("sessions-title");
    title.scrollIntoView = vi.fn();
    await userEvent.click(screen.getByRole("button", { name: /www\.example\.com \(93\.184\.216\.34\)/ }));
    await waitFor(() => expect(title.scrollIntoView).toHaveBeenCalled());
  });
});

describe("SessionDetail: ExplainView, TlsView y SessionHttp", () => {
  it("el detalle muestra en orden: nota, explicación, TLS, HTTP y conversación", async () => {
    api.sessionTls.mockResolvedValue({
      tls: true, incomplete: false, client: { ja4: "t13d1516h2_a_b", sni: "x.test", alpn: "h2", ciphers: 15, complete: true },
      server: { version: "TLS 1.2", cipher: "C" }, certificate: null, certificate_hidden: false,
    });
    api.sessionHttp.mockResolvedValue({ exchanges: [{ ...httpItem, request_bytes: 0, file: null }], incomplete: false });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    const note = await screen.findByLabelText("Nota del analista");
    const explain = await screen.findByRole("heading", { name: /^En palabras simples/ });
    const tls = await screen.findByRole("heading", { name: /^TLS \(cifrado\)/ });
    const http = await screen.findByRole("heading", { level: 3, name: /^HTTP/ });
    const stream = screen.getByRole("heading", { name: /^Conversación/ });
    expect(follows(note, explain) && follows(explain, tls) && follows(tls, http) && follows(http, stream)).toBe(true);
    expect(api.explain).toHaveBeenCalledWith(1, expect.any(AbortSignal));
  });

  it("para una sesión UDP no hay explicación TCP de HTTP ni TLS (solo la explicación)", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [{ ...sess(1), protocol: "UDP" }] });
    api.explain.mockResolvedValue({ protocol: "UDP", outcome: null, summary: ["UDP no abre una conexión."], steps: [] });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    expect(await screen.findByText("UDP no abre una conexión.")).toBeInTheDocument();
    expect(api.sessionHttp).not.toHaveBeenCalled();
    expect(api.sessionTls).not.toHaveBeenCalled();
    expect(screen.queryByRole("heading", { name: /^TLS/ })).toBeNull();
  });
});

describe("App: secciones, onNavigate y onCapture", () => {
  const ready = async (props) => {
    render(<App {...props} />);
    await waitFor(() => expect(api.capture).toHaveBeenCalled());
  };
  const titles = () => screen.queryAllByRole("heading", { level: 2 }).map((h) => h.textContent.trim());

  it("panorama: caso guiado, resumen, tráfico, riesgo y quién habla; nada más", async () => {
    await ready({ section: "panorama" });
    await screen.findByRole("heading", { name: "Puntaje de riesgo" });
    await screen.findByRole("heading", { name: "Quién más habla" });
    expect(h2(/Caso guiado/)).toBeInTheDocument();
    expect(h2("Resumen")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Alertas" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Sesiones" })).toBeNull();
  });

  it("panorama con otra captura que no es el demo: sin caso guiado", async () => {
    api.capture.mockResolvedValue(summary("otra.pcap"));
    await ready({ section: "panorama" });
    await screen.findByRole("heading", { name: "Resumen" });
    expect(screen.queryByRole("heading", { name: /Caso guiado/ })).toBeNull();
  });

  it("alertas: tabla de alertas y mapa ATT&CK", async () => {
    await ready({ section: "alertas" });
    await screen.findByRole("heading", { name: "Alertas" });
    expect(await screen.findByRole("heading", { level: 2, name: /Mapa MITRE/ })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Resumen" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Sesiones" })).toBeNull();
  });

  it("equipos, trafico, indicadores y sesiones muestran solo lo suyo", async () => {
    const only = async (section, wanted, unwanted) => {
      const { unmount } = render(<App section={section} />);
      await waitFor(() => expect(api.capture).toHaveBeenCalled());
      await waitFor(() => expect(screen.queryByRole("button", { name: "Cargar el ejemplo" })).toBeNull());
      await screen.findByRole("heading", { name: wanted[0] });
      for (const w of wanted) expect(screen.getByRole("heading", { name: w })).toBeInTheDocument();
      for (const u of unwanted) expect(screen.queryByRole("heading", { name: u })).toBeNull();
      unmount();
    };
    await only("equipos", ["Equipos"], ["Resumen", "DNS", "Sesiones"]);
    await only("trafico", ["DNS", "HTTP sin cifrar"], ["Equipos", "Sesiones"]);
    await only("indicadores", ["Indicadores (IOC)"], ["Equipos", "Sesiones"]);
    await only("sesiones", ["Sesiones"], ["Equipos", "Resumen", "Indicadores (IOC)"]);
  });

  it("sesiones: el detalle de una sesión se abre en esa sección", async () => {
    await ready({ section: "sesiones" });
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    expect(await screen.findByRole("heading", { name: "Sesión 1" })).toBeInTheDocument();
  });

  it("sin captura la entrada se ve en «all» y «panorama» y «Abrir soporte de red» llama a onOpenSupport; en otras secciones va EmptySection", async () => {
    api.capture.mockRejectedValue(Object.assign(new Error("x"), { status: 409 }));
    const onOpenSupport = vi.fn();
    for (const section of ["all", "panorama"]) {
      const { unmount } = render(<App section={section} onOpenSupport={onOpenSupport} />);
      await userEvent.click(await screen.findByRole("button", { name: "Abrir soporte de red" }));
      expect(titles()).toContain("Empezá analizando una captura");
      unmount();
    }
    expect(onOpenSupport).toHaveBeenCalledTimes(2);
    render(<App section="alertas" onOpenSupport={onOpenSupport} />);
    expect(await screen.findByRole("heading", { level: 2, name: "Alertas y ATT&CK" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Abrir soporte de red" })).toBeNull();
    expect(titles()).not.toContain("Empezá analizando una captura");
  });

  it("onCapture recibe null al principio y el resumen cuando se carga la captura", async () => {
    const onCapture = vi.fn();
    render(<App onCapture={onCapture} />);
    await waitFor(() => expect(onCapture).toHaveBeenLastCalledWith(expect.objectContaining({ source: "demo.pcap" })));
    expect(onCapture.mock.calls[0][0]).toBeNull();
  });

  it("onCapture recibe null otra vez al salir del demo", async () => {
    api.closeCapture.mockResolvedValue({ cleared: true });
    const onCapture = vi.fn();
    render(<App onCapture={onCapture} />);
    await userEvent.click(await screen.findByRole("button", { name: "Salir del demo" }));
    await waitFor(() => expect(onCapture).toHaveBeenLastCalledWith(null));
  });

  it("filtrar por IP (desde un nodo del grafo) llama a onNavigate('sesiones')", async () => {
    const onNavigate = vi.fn();
    render(<App section="equipos" onNavigate={onNavigate} />);
    await userEvent.click(await screen.findByRole("button", { name: /www\.example\.com \(93\.184\.216\.34\)/ }));
    expect(onNavigate).toHaveBeenCalledWith("sesiones");
  });

  it("«Ver sesiones» de una alerta llama a onNavigate('sesiones')", async () => {
    const onNavigate = vi.fn();
    render(<App section="alertas" onNavigate={onNavigate} />);
    await screen.findByRole("heading", { name: "Alertas" });
    await userEvent.click(await screen.findByText("Escaneo de puertos"));
    await userEvent.click(await screen.findByRole("button", { name: /sesiones/i }));
    expect(onNavigate).toHaveBeenCalledWith("sesiones");
  });

  it("un paso del caso guiado con salto navega a su sección", async () => {
    const onNavigate = vi.fn();
    render(<App section="panorama" onNavigate={onNavigate} />);
    await userEvent.click(await screen.findByRole("button", { name: "Ir a DNS" }));
    expect(onNavigate).toHaveBeenCalledWith("trafico");
  });
});

describe("CapturesView: sección de acceso remoto", () => {
  it("la sección «remoto» muestra la tarjeta de acceso remoto y no las demás", async () => {
    api.remoteAccess.mockResolvedValue({ total: 0, services: [] });
    render(<App section="remoto" />);
    // «Acceso remoto» también es el título de la pantalla vacía: se espera a la tarjeta real
    expect(await screen.findByText(/No hay conexiones de acceso remoto/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Alertas" })).toBeNull();
    expect(api.remoteAccess).toHaveBeenCalled();
  });

  it("las demás secciones no piden el acceso remoto", async () => {
    render(<App section="alertas" />);
    await screen.findByRole("heading", { name: "Alertas" });
    expect(api.remoteAccess).not.toHaveBeenCalled();
  });
});
