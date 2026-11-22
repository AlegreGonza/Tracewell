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
    demo: vi.fn(), analyze: vi.fn(), capture: vi.fn(), sessions: vi.fn(), alerts: vi.fn(),
    sessionPackets: vi.fn(), packet: vi.fn(), timeline: vi.fn(), interfaces: vi.fn(), liveStart: vi.fn(),
    liveStatus: vi.fn(), liveStop: vi.fn(), exportUrl: vi.fn(() => "/api/export"),
    iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn(), saveNote: vi.fn(), reportUrl: vi.fn(() => "/api/report"),
  },
}));
import { api } from "../api/client.js";
import App from "./CapturesView.jsx";

const NO_IOCS = { loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 };
const summary = {
  source: "demo.pcap", format: "pcap", linktype: 1, snaplen: 65535, alerts: 2, rules: 3,
  stats: { sessions: 3, packets: 9, bytes: 900, by_protocol: {}, non_ip: 0, malformed: 0 },
};
const sess = (id, src) => ({
  id, protocol: "TCP", src_ip: src, src_port: 1000 + id, dst_ip: "10.0.0.9", dst_port: 80,
  packets: 3, bytes: 300, first_ts: 1, last_ts: 2, duration: 1,
});
const alertOf = (name, src) => ({
  rule_id: name, name, severity: "high", mitre_technique: "T1046", mitre_name: "n", mitre_tactic: "t",
  description: "d", src_ip: src, dst_ip: "10.0.0.9", first_ts: 1700000000, evidence: {},
});
// El caso guiado del demo repite ese texto en su propio botón: se busca el de la tabla de alertas.
const viewSessionsBtn = () => within(screen.getByRole("heading", { name: "Alertas" }).closest("section")).getByRole("button", { name: "Ver las sesiones de 192.168.1.66" });
const ALL = [sess(1, "10.0.0.1"), sess(2, "192.168.1.66"), sess(3, "192.168.1.66")];

beforeEach(() => {
  vi.clearAllMocks();
  api.timeline.mockResolvedValue({ start: 0, bucket_seconds: 1, packets: [], bytes: [] });
  api.capture.mockResolvedValue(summary);
  api.alerts.mockResolvedValue([alertOf("Escaneo", "192.168.1.66"), alertOf("Otra", "10.0.0.1")]);
  api.sessions.mockImplementation(async (p) => {
    const items = p.ip ? ALL.filter((s) => s.src_ip === p.ip) : ALL;
    return { total: items.length, items };
  });
  api.iocs.mockResolvedValue(NO_IOCS);
  api.interfaces.mockResolvedValue([]);
  api.sessionPackets.mockResolvedValue({ items: [], has_more: false });
});

afterEach(() => vi.useRealTimers());

describe("App: de la alerta a las sesiones", () => {
  it("'Ver las sesiones' filtra la tabla por la IP de origen de la alerta", async () => {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    await userEvent.click(viewSessionsBtn());
    await vi.waitFor(() => expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ ip: "192.168.1.66", protocol: "", port: "" }));
    expect(screen.getByLabelText("IP")).toHaveValue("192.168.1.66");
    expect(await screen.findByText("2 coinciden")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Ver paquetes de la sesión 1" })).toBeNull();
    expect(screen.getByRole("button", { name: "Ver paquetes de la sesión 2" })).toBeInTheDocument();
  });

  it("reemplaza los filtros que hubiera (protocolo y puerto se limpian) y vuelve a la página 1", async () => {
    render(<App />);
    await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" });
    await userEvent.type(screen.getByLabelText("Protocolo"), "UDP");
    await userEvent.type(screen.getByLabelText("Puerto"), "53");
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    await vi.waitFor(() => expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ protocol: "UDP", port: "53" }));
    await userEvent.click(screen.getByRole("button", { name: /Otra/ }));
    await userEvent.click(screen.getByRole("button", { name: "Ver las sesiones de 10.0.0.1" }));
    await vi.waitFor(() => expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ ip: "10.0.0.1", protocol: "", port: "", offset: 0 }));
    expect(screen.getByLabelText("Protocolo")).toHaveValue("");
    expect(screen.getByLabelText("Puerto")).toHaveValue("");
  });

  it("cierra el detalle de la sesión seleccionada", async () => {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    await screen.findByRole("complementary");
    await userEvent.click(screen.getByRole("button", { name: /Escaneo/ }));
    await userEvent.click(viewSessionsBtn());
    await vi.waitFor(() => expect(screen.queryByRole("complementary")).toBeNull());
  });

  it("desplaza hasta el título de Sesiones si el navegador soporta scrollIntoView", async () => {
    const scroll = vi.fn();
    const original = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = scroll;
    try {
      render(<App />);
      await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
      await userEvent.click(viewSessionsBtn());
      await vi.waitFor(() => expect(scroll).toHaveBeenCalledWith({ behavior: "smooth", block: "start" }));
      expect(scroll.mock.instances[0].id).toBe("sessions-title");
    } finally {
      Element.prototype.scrollIntoView = original;
    }
  });

  it("sin scrollIntoView (jsdom) no falla", async () => {
    expect(Element.prototype.scrollIntoView).toBeUndefined();
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    await userEvent.click(viewSessionsBtn());
    await new Promise((r) => setTimeout(r, 10));
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("App: triaje", () => {
  it("el panel de IOC aparece entre las alertas y las sesiones y la barra ofrece el informe", async () => {
    render(<App />);
    const ioc = await screen.findByRole("region", { name: "Indicadores (IOC)" });
    const alerts = screen.getByRole("region", { name: "Alertas" });
    const sessions = screen.getByRole("region", { name: "Sesiones" });
    expect(alerts.compareDocumentPosition(ioc) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(ioc.compareDocumentPosition(sessions) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByRole("link", { name: "Informe HTML" })).toHaveAttribute("href", "/api/report");
  });

  it("sin captura no hay panel de IOC ni enlace al informe", async () => {
    api.capture.mockRejectedValue(Object.assign(new Error("no"), { status: 409 }));
    render(<App />);
    await screen.findByText("Empezá analizando una captura");
    expect(screen.queryByRole("region", { name: "Indicadores (IOC)" })).toBeNull();
    expect(screen.getByText("Informe HTML")).toHaveAttribute("aria-disabled", "true");
  });

  it("cargar una lista de IOC recarga las sesiones con la marca", async () => {
    api.loadIocs.mockImplementation(async () => {
      ALL[0] = { ...ALL[0], ioc: ["ip:10.0.0.9"] };
      return { loaded: true, source: "feed.txt", ips: 1, networks: 0, domains: 0, sessions: 3 };
    });
    try {
      render(<App />);
      await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" });
      const before = api.sessions.mock.calls.length;
      await userEvent.type(screen.getByLabelText("Ruta del archivo de indicadores"), "feed.txt{Enter}");
      expect(await screen.findByText(/feed\.txt: 1 IP/)).toBeInTheDocument();
      await vi.waitFor(() => expect(api.sessions.mock.calls.length).toBeGreaterThan(before));
      const row = screen.getByRole("button", { name: "Ver paquetes de la sesión 1" }).closest("tr");
      expect(await within(row).findByText("IOC")).toBeInTheDocument();
    } finally {
      ALL[0] = sess(1, "10.0.0.1");
    }
  });

  it("guardar una nota actualiza el detalle seleccionado y recarga la tabla", async () => {
    api.saveNote.mockResolvedValue({ id: 1, note: "mi nota", reviewed: true });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    const detail = await screen.findByRole("complementary");
    const before = api.sessions.mock.calls.length;
    api.sessions.mockImplementation(async () => ({
      total: 3, items: [{ ...ALL[0], note: "mi nota", reviewed: true }, ALL[1], ALL[2]],
    }));
    await userEvent.type(within(detail).getByLabelText("Nota del analista"), "mi nota");
    await userEvent.click(within(detail).getByRole("checkbox", { name: "Marcar como revisada" }));
    await userEvent.click(within(detail).getByRole("button", { name: "Guardar nota" }));
    expect(api.saveNote).toHaveBeenCalledWith(1, { note: "mi nota", reviewed: true });
    await vi.waitFor(() => expect(api.sessions.mock.calls.length).toBeGreaterThan(before));
    const row = (await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" })).closest("tr");
    expect(await within(row).findByText("nota")).toHaveAttribute("title", "mi nota");
    expect(within(row).getByText("✓")).toBeInTheDocument();
    expect(within(detail).getByLabelText("Nota del analista")).toHaveValue("mi nota");
  });

  it("tras guardar, el aviso 'Guardada' sigue visible dentro de la App", async () => {
    api.saveNote.mockResolvedValue({ id: 1, note: "mi nota", reviewed: false });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    const detail = await screen.findByRole("complementary");
    await userEvent.type(within(detail).getByLabelText("Nota del analista"), "mi nota");
    await userEvent.click(within(detail).getByRole("button", { name: "Guardar nota" }));
    await vi.waitFor(() => expect(api.saveNote).toHaveBeenCalled());
    expect(await within(detail).findByText("Guardada", {}, { timeout: 500 })).toBeInTheDocument();
  });

  it("un error al guardar la nota sale en el banner global", async () => {
    api.saveNote.mockRejectedValue(Object.assign(new Error("demasiadas notas (máximo 5000)"), { status: 409 }));
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    const detail = await screen.findByRole("complementary");
    await userEvent.type(within(detail).getByLabelText("Nota del analista"), "x");
    await userEvent.click(within(detail).getByRole("button", { name: "Guardar nota" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("demasiadas notas");
  });

  it("un error al cargar la lista de IOC sale en el banner global", async () => {
    api.loadIocs.mockRejectedValue(Object.assign(new Error("línea 1: no es una IP"), { status: 422 }));
    render(<App />);
    await userEvent.type(await screen.findByLabelText("Ruta del archivo de indicadores"), "mala.txt{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent("línea 1: no es una IP");
  });

  it("un análisis nuevo refresca el conteo 'N sesiones coinciden' del panel de IOC", async () => {
    api.iocs.mockResolvedValue({ loaded: true, source: "feed.txt", ips: 1, networks: 0, domains: 0, sessions: 3 });
    api.demo.mockResolvedValue({ ...summary, source: "demo.pcap" });
    render(<App />);
    expect(await screen.findByText(/3 sesiones coinciden/)).toBeInTheDocument();
    const before = api.iocs.mock.calls.length;
    api.iocs.mockResolvedValue({ loaded: true, source: "feed.txt", ips: 1, networks: 0, domains: 0, sessions: 8 });
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    expect(await screen.findByText(/8 sesiones coinciden/)).toBeInTheDocument();
    expect(api.iocs.mock.calls.length).toBeGreaterThan(before);
    expect(screen.queryByText(/3 sesiones coinciden/)).toBeNull();
  });

  it("un análisis nuevo limpia el filtro puesto desde una alerta", async () => {
    api.analyze.mockResolvedValue({ ...summary, source: "nuevo.pcap" });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    await userEvent.click(viewSessionsBtn());
    await screen.findByText("2 coinciden");
    await userEvent.type(screen.getByLabelText(/Ruta del archivo \.pcap/), "otro.pcap{Enter}");
    await screen.findByText(/nuevo\.pcap/);
    await vi.waitFor(() => expect(screen.getByLabelText("IP")).toHaveValue(""));
  });
});
