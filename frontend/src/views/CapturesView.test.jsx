import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api/client.js", () => ({
  api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    hostsByMac: vi.fn(() => Promise.resolve({ total: 0, items: [] })), caseTimeline: vi.fn(() => Promise.resolve({ host: null, total: 0, truncated: false, items: [] })), remoteAccess: vi.fn(() => Promise.resolve({ total: 0, services: [] })), httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`),
    demo: vi.fn(),
    analyze: vi.fn(),
    capture: vi.fn(),
    sessions: vi.fn(),
    alerts: vi.fn(),
    sessionPackets: vi.fn(),
    packet: vi.fn(),
    timeline: vi.fn(),
    interfaces: vi.fn(),
    liveStart: vi.fn(),
    liveStatus: vi.fn(),
    liveStop: vi.fn(),
    iocs: vi.fn(),
    loadIocs: vi.fn(),
    clearIocs: vi.fn(),
    saveNote: vi.fn(),
    reportUrl: vi.fn(() => "/api/report"),
    exportUrl: vi.fn((f = {}) => {
      const q = new URLSearchParams(f).toString();
      return `/api/export${q ? `?${q}` : ""}`;
    }),
  },
}));
import { api } from "../api/client.js";
import App from "./CapturesView.jsx";

const NO_IOCS = { loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 };
const apiErr = (status, msg) => Object.assign(new Error(msg), { status });
const summary = (source, packets = 10) => ({
  source,
  format: "pcap",
  linktype: 1,
  snaplen: 65535,
  alerts: 1,
  rules: 3,
  stats: {
    sessions: 2,
    packets,
    bytes: 1000,
    by_protocol: { TCP: { sessions: 2, packets, bytes: 1000 } },
    non_ip: 0,
    malformed: 0,
  },
});
const sess = (id) => ({
  id,
  protocol: "TCP",
  src_ip: "10.0.0.1",
  src_port: 1000 + id,
  dst_ip: "10.0.0.2",
  dst_port: 80,
  packets: 5,
  bytes: 500,
  first_ts: 1700000000,
  last_ts: 1700000001,
  duration: 1,
});
const alertItem = {
  rule_id: "R1",
  name: "Escaneo de puertos",
  severity: "high",
  mitre_technique: "T1046",
  mitre_name: "Network Service Discovery",
  mitre_tactic: "Discovery",
  description: "d",
  src_ip: "1.1.1.1",
  dst_ip: "2.2.2.2",
  first_ts: 1700000000,
  evidence: {},
};

beforeEach(() => {
  vi.clearAllMocks();
  api.timeline.mockResolvedValue({ start: 0, bucket_seconds: 1, packets: [], bytes: [] });
  api.capture.mockRejectedValue(apiErr(409, "No hay captura"));
  api.alerts.mockResolvedValue([alertItem]);
  api.sessions.mockResolvedValue({ total: 2, items: [sess(1), sess(2)] });
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue(NO_IOCS);
  api.sessionPackets.mockResolvedValue({
    items: [{ index: 3, ts: 1700000000, caplen: 60, origlen: 60, snaplen_limited: false }],
    has_more: false,
  });
  api.packet.mockResolvedValue({
    index: 3, ts: 1700000000, caplen: 60, origlen: 60, snaplen_limited: false, session_id: 1,
    endpoints: null, hexdump: "HEX-DEL-PAQUETE",
  });
  api.demo.mockResolvedValue(summary("demo.pcap", 42));
  api.analyze.mockResolvedValue(summary("nuevo.pcap", 99));
});

afterEach(() => {
  delete window.pywebview;
});

describe("App", () => {
  it("pick_file que rechaza: Examinar muestra el aviso de error en pantalla", async () => {
    window.pywebview = { api: { pick_file: vi.fn().mockRejectedValue(new Error("selector roto")) } };
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(screen.getByRole("button", { name: "Examinar…" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("selector roto");
    expect(api.analyze).not.toHaveBeenCalled();
  });

  it("al montar con 409 muestra la bienvenida y ningún error", async () => {
    render(<App />);
    expect(await screen.findByText("Empezá analizando una captura")).toBeInTheDocument();
    await vi.waitFor(() => expect(api.capture).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText("Resumen")).toBeNull();
    expect(screen.getByText("Exportar JSON")).toHaveAttribute("aria-disabled", "true");
  });

  it("al montar con 200 retoma el análisis", async () => {
    api.capture.mockResolvedValue(summary("previo.pcap"));
    render(<App />);
    expect(await screen.findByText(/previo\.pcap/)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /Escaneo de puertos/ })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" })).toBeInTheDocument();
    expect(screen.queryByText("Empezá analizando una captura")).toBeNull();
    expect(screen.getByRole("link", { name: "Exportar JSON" })).toBeInTheDocument();
  });

  it("error de red/500 al montar -> banner", async () => {
    api.capture.mockRejectedValue(apiErr(0, "No se pudo conectar con la API. ¿Está en marcha?"));
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("No se pudo conectar");
  });

  it("Modo demo carga resumen, alertas y sesiones", async () => {
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    expect(await screen.findByText(/demo\.pcap/)).toBeInTheDocument();
    expect(api.demo).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: /Escaneo de puertos/ })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Ver paquetes de la sesión 2" })).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("error de demo -> banner y vuelve la bienvenida", async () => {
    api.demo.mockRejectedValue(apiErr(500, "falló el demo"));
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("falló el demo");
    expect(screen.getByText("Empezá analizando una captura")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Modo demo" })).toBeEnabled();
  });

  it("cerrar el banner lo quita", async () => {
    api.demo.mockRejectedValue(apiErr(500, "falló"));
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    await userEvent.click(await screen.findByRole("button", { name: "Cerrar aviso" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("analizar una ruta llama api.analyze con la ruta recortada", async () => {
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.type(screen.getByLabelText(/Ruta del archivo .pcap/), " C:\\a.pcap ");
    await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
    expect(api.analyze).toHaveBeenCalledWith("C:\\a.pcap");
    expect(await screen.findByText(/nuevo\.pcap/)).toBeInTheDocument();
  });

  it("analizar un archivo nuevo limpia filtros y selección", async () => {
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" });

    // aplicar filtro y seleccionar sesión
    await userEvent.type(screen.getByLabelText("Protocolo"), "TCP");
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    await vi.waitFor(() => expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ protocol: "TCP" }));
    expect(screen.getByRole("link", { name: "Exportar JSON" })).toHaveAttribute("href", expect.stringContaining("protocol=TCP"));
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    await screen.findByText("Sesión 1");

    // analizar otro archivo
    await userEvent.type(screen.getByLabelText(/Ruta del archivo .pcap/), "otro.pcap");
    await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
    await screen.findByText(/nuevo\.pcap/);

    await vi.waitFor(() => expect(screen.queryByText("Sesión 1")).toBeNull());
    expect(screen.getByLabelText("Protocolo")).toHaveValue("");
    expect(screen.getByRole("link", { name: "Exportar JSON" })).toHaveAttribute("href", "/api/export");
    await vi.waitFor(() => expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ protocol: "", offset: 0 }));
  });

  it("seleccionar una sesión abre el detalle y cerrarlo lo quita", async () => {
    api.capture.mockResolvedValue(summary("previo.pcap"));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 2" }));
    const detail = await screen.findByRole("complementary");
    expect(within(detail).getByText("Sesión 2")).toBeInTheDocument();
    expect(await within(detail).findByText("HEX-DEL-PAQUETE")).toBeInTheDocument();
    expect(api.sessionPackets).toHaveBeenCalledWith(2, { limit: 50, offset: 0 });
    await userEvent.click(within(detail).getByRole("button", { name: "Cerrar" }));
    expect(screen.queryByRole("complementary")).toBeNull();
  });

  it("Cargar el ejemplo (bienvenida) llama api.demo y muestra el análisis", async () => {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Cargar el ejemplo" }));
    expect(await screen.findByText(/demo\.pcap/)).toBeInTheDocument();
    expect(api.demo).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" })).toBeInTheDocument();
    expect(screen.queryByText("Empezá analizando una captura")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cargar el ejemplo" })).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("mientras carga el demo la bienvenida se reemplaza por 'Analizando la captura…'", async () => {
    let resolve;
    api.demo.mockReturnValue(new Promise((r) => { resolve = r; }));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Cargar el ejemplo" }));
    expect(await screen.findByText("Analizando la captura…")).toBeInTheDocument();
    expect(screen.queryByText("Empezá analizando una captura")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cargar el ejemplo" })).toBeNull();
    expect(screen.getByRole("button", { name: "Modo demo" })).toBeDisabled();
    expect(api.demo).toHaveBeenCalledTimes(1);
    resolve(summary("demo.pcap", 42));
    expect(await screen.findByText(/demo\.pcap/)).toBeInTheDocument();
    expect(screen.queryByText("Analizando la captura…")).toBeNull();
  });

  it("si api.demo rechaza desde la bienvenida: vuelve la bienvenida y el banner muestra el mensaje", async () => {
    api.demo.mockRejectedValue(apiErr(500, "demo caído"));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Cargar el ejemplo" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("demo caído");
    expect(screen.getByRole("region", { name: "Empezá analizando una captura" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cargar el ejemplo" })).toBeEnabled();
    expect(screen.queryByText("Analizando la captura…")).toBeNull();
    // se puede reintentar
    api.demo.mockResolvedValue(summary("demo.pcap", 42));
    await userEvent.click(screen.getByRole("button", { name: "Cargar el ejemplo" }));
    expect(await screen.findByText(/demo\.pcap/)).toBeInTheDocument();
  });

  it("'Modo demo' sigue siendo un único botón accesible con la bienvenida visible", async () => {
    render(<App />);
    await screen.findByRole("button", { name: "Cargar el ejemplo" });
    expect(screen.getAllByRole("button", { name: "Modo demo" })).toHaveLength(1);
  });

  it("un error de la tabla de alertas aparece en el banner global", async () => {
    api.capture.mockResolvedValue(summary("previo.pcap"));
    api.alerts.mockRejectedValue(apiErr(500, "alertas rotas"));
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("alertas rotas");
  });
});

describe("App: barra de captura en vivo fuera de <main>", () => {
  const IFACES = [{ name: "eth0", description: "eth0" }];
  const liveBar = () => screen.getByRole("region", { name: "Captura en vivo" });
  const expectOutsideAndAfterMain = () => {
    const main = screen.getByRole("main");
    const live = liveBar();
    expect(main.contains(live)).toBe(false);
    expect(live.contains(main)).toBe(false);
    expect(main.compareDocumentPosition(live) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // último hijo del contenedor .app
    expect(live.parentElement).toBe(main.parentElement);
    expect(live.parentElement.lastElementChild).toBe(live);
  };

  it("estado vacío: la barra está fuera de <main> y después en el orden del documento", async () => {
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    expectOutsideAndAfterMain();
  });

  it("con un análisis cargado sigue fuera de <main> y después de él", async () => {
    api.capture.mockResolvedValue(summary("previo.pcap"));
    render(<App />);
    await screen.findByRole("button", { name: /Escaneo de puertos/ });
    expectOutsideAndAfterMain();
    expect(within(screen.getByRole("main")).queryByText("Captura en vivo")).toBeNull();
  });

  it("sigue presente (y fuera de <main>) mientras la app está ocupada", async () => {
    api.demo.mockReturnValue(new Promise(() => {}));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Cargar el ejemplo" }));
    await screen.findByText("Analizando la captura…");
    expectOutsideAndAfterMain();
  });

  it("también está presente con el banner de error de arranque", async () => {
    api.capture.mockRejectedValue(apiErr(0, "sin API"));
    render(<App />);
    await screen.findByRole("alert");
    expectOutsideAndAfterMain();
  });

  it("está colapsada por defecto: sin selector de interfaz ni llamadas a la API", async () => {
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    const toggle = within(liveBar()).getByRole("button", { name: "Mostrar" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByLabelText("Interfaz")).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Interfaz" })).toBeNull();
    expect(api.interfaces).not.toHaveBeenCalled();
  });

  it("abrirla carga las interfaces una sola vez y muestra el selector; cerrar y reabrir no recarga", async () => {
    api.interfaces.mockResolvedValue(IFACES);
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    const select = await screen.findByLabelText("Interfaz");
    expect(select).toHaveValue("eth0");
    expect(within(liveBar()).getByRole("button", { name: "Ocultar" })).toHaveAttribute("aria-expanded", "true");
    expect(api.interfaces).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("main").contains(select)).toBe(false);

    await userEvent.click(within(liveBar()).getByRole("button", { name: "Ocultar" }));
    expect(screen.queryByLabelText("Interfaz")).toBeNull();
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    expect(await screen.findByLabelText("Interfaz")).toBeInTheDocument();
    expect(api.interfaces).toHaveBeenCalledTimes(1);
  });

  it("con un análisis cargado, abrir la barra no altera alertas ni sesiones", async () => {
    api.capture.mockResolvedValue(summary("previo.pcap"));
    api.interfaces.mockResolvedValue(IFACES);
    render(<App />);
    await screen.findByRole("button", { name: /Escaneo de puertos/ });
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    await screen.findByLabelText("Interfaz");
    const main = screen.getByRole("main");
    expect(within(main).getByRole("button", { name: /Escaneo de puertos/ })).toBeInTheDocument();
    expect(within(main).getByRole("button", { name: "Ver paquetes de la sesión 1" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
    expectOutsideAndAfterMain();
  });

  it("iniciar captura llama api.liveStart y al detener el análisis reemplaza al actual", async () => {
    api.capture.mockResolvedValue(summary("previo.pcap"));
    api.interfaces.mockResolvedValue(IFACES);
    api.liveStart.mockResolvedValue({ state: "running", packets: 0, bytes: 0, seconds: 0, reason: null });
    api.liveStop.mockResolvedValue({
      capture: { reason: "manual" },
      analysis: summary("en-vivo.pcap", 7),
    });
    render(<App />);
    await screen.findByText(/previo\.pcap/);
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    await screen.findByLabelText("Interfaz");
    await userEvent.click(screen.getByRole("button", { name: "Iniciar captura" }));
    expect(api.liveStart).toHaveBeenCalledWith({ interface: "eth0" });
    await userEvent.click(await screen.findByRole("button", { name: "Detener y analizar" }));
    expect(api.liveStop).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/en-vivo\.pcap/)).toBeInTheDocument();
    expect(screen.queryByText(/previo\.pcap/)).toBeNull();
    expect(within(liveBar()).getByRole("status")).toHaveTextContent("Captura terminada");
    expectOutsideAndAfterMain();
  });

  it("detener desde la bienvenida reemplaza la bienvenida por el análisis", async () => {
    api.interfaces.mockResolvedValue(IFACES);
    api.liveStart.mockResolvedValue({ state: "running", packets: 0, bytes: 0, seconds: 0, reason: null });
    api.liveStop.mockResolvedValue({ capture: { reason: "manual" }, analysis: summary("en-vivo.pcap", 7) });
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    await screen.findByLabelText("Interfaz");
    await userEvent.click(screen.getByRole("button", { name: "Iniciar captura" }));
    await userEvent.click(await screen.findByRole("button", { name: "Detener y analizar" }));
    expect(await screen.findByText(/en-vivo\.pcap/)).toBeInTheDocument();
    expect(screen.queryByText("Empezá analizando una captura")).toBeNull();
  });

  it("'Iniciar captura' queda deshabilitado mientras la app está ocupada", async () => {
    api.interfaces.mockResolvedValue(IFACES);
    api.demo.mockReturnValue(new Promise(() => {}));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Cargar el ejemplo" }));
    await screen.findByText("Analizando la captura…");
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    await screen.findByLabelText("Interfaz");
    expect(screen.getByRole("button", { name: "Iniciar captura" })).toBeDisabled();
  });

  it("si api.liveStart rechaza, el aviso (role alert) aparece dentro de <main> y no en la barra", async () => {
    api.interfaces.mockResolvedValue(IFACES);
    api.liveStart.mockRejectedValue(apiErr(403, "ejecutá Tracewell como administrador"));
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    await screen.findByLabelText("Interfaz");
    await userEvent.click(screen.getByRole("button", { name: "Iniciar captura" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("administrador");
    expect(screen.getByRole("main").contains(alert)).toBe(true);
    expect(liveBar().contains(alert)).toBe(false);
    expect(api.liveStart).toHaveBeenCalledTimes(1);
    // la barra sigue operable y se puede reintentar
    expect(screen.getByRole("button", { name: "Iniciar captura" })).toBeEnabled();
  });

  it("si api.interfaces rechaza, el aviso va a <main> y la barra muestra 'No se encontraron interfaces'", async () => {
    api.interfaces.mockRejectedValue(apiErr(500, "sin interfaces"));
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    await userEvent.click(within(liveBar()).getByRole("button", { name: "Mostrar" }));
    const alert = await screen.findByRole("alert");
    expect(screen.getByRole("main").contains(alert)).toBe(true);
    expect(within(liveBar()).getByText("No se encontraron interfaces.")).toBeInTheDocument();
  });
});
