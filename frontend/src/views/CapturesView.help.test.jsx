import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
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
    demo: vi.fn(), analyze: vi.fn(), capture: vi.fn(), sessions: vi.fn(), alerts: vi.fn(), timeline: vi.fn(),
    sessionPackets: vi.fn(), packet: vi.fn(), stream: vi.fn(), interfaces: vi.fn(), liveStart: vi.fn(),
    liveStatus: vi.fn(), liveStop: vi.fn(), exportUrl: vi.fn(() => "/api/export"), closeCapture: vi.fn(),
    iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn(), saveNote: vi.fn(), reportUrl: vi.fn(() => "/api/report"),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`),
  },
}));
import { api } from "../api/client.js";
import App from "./CapturesView.jsx";

const summary = {
  source: "demo.pcap", format: "pcap", linktype: 1, snaplen: 65535, alerts: 1, rules: 8,
  stats: { sessions: 1, packets: 1, bytes: 1, by_protocol: {}, non_ip: 0, malformed: 0 },
};
const alertOf = {
  rule_id: "port_scan", name: "Escaneo de puertos", severity: "high", mitre_technique: "T1046", mitre_name: "Network Service Discovery",
  mitre_tactic: "Discovery", description: "d", src_ip: "192.168.1.66", dst_ip: "10.0.0.9", first_ts: 1700000000, evidence: {},
};

beforeEach(() => {
  vi.clearAllMocks();
  api.capture.mockResolvedValue(summary);
  api.alerts.mockResolvedValue([alertOf]);
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
  api.timeline.mockResolvedValue({ start: 0, bucket_seconds: 1, packets: [], bytes: [] });
  api.sessions.mockResolvedValue({ total: 0, items: [] });
});

describe("App: glosario y mapa ATT&CK", () => {
  it("el botón Glosario abre y cierra el glosario (también sin captura)", async () => {
    api.capture.mockRejectedValue(Object.assign(new Error("x"), { status: 409 }));
    render(<App />);
    await screen.findByRole("button", { name: "Modo demo" });
    expect(screen.queryByRole("heading", { name: "Glosario" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Glosario" }));
    expect(screen.getByRole("heading", { name: "Glosario" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Glosario" })); // alterna
    expect(screen.queryByRole("heading", { name: "Glosario" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Glosario" }));
    await userEvent.click(within(screen.getByRole("heading", { name: "Glosario" }).closest("section")).getByRole("button", { name: "Cerrar" }));
    expect(screen.queryByRole("heading", { name: "Glosario" })).toBeNull();
  });

  it("el glosario no pide nada a la API", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Resumen" });
    const before = api.alerts.mock.calls.length;
    await userEvent.click(screen.getByRole("button", { name: "Glosario" }));
    await userEvent.type(screen.getByLabelText("Buscar en el glosario"), "ttl");
    expect(api.alerts.mock.calls.length).toBe(before);
  });

  it("el mapa ATT&CK aparece justo después de las alertas y se ilumina con ellas", async () => {
    render(<App />);
    const attack = await screen.findByRole("heading", { name: /Mapa MITRE/ });
    const alerts = screen.getByRole("heading", { name: "Alertas" });
    expect(alerts.compareDocumentPosition(attack) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Resumen" }).compareDocumentPosition(attack) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(await screen.findByRole("link", { name: "T1046" })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1046/");
    expect(document.querySelectorAll("li.tactic.hit")).toHaveLength(1);
  });

  it("el mapa y las alertas piden las alertas (una vez cada uno) al cargar", async () => {
    render(<App />);
    await screen.findByRole("link", { name: "T1046" });
    await waitFor(() => expect(api.alerts.mock.calls.length).toBeGreaterThanOrEqual(2));
    expect(api.alerts.mock.calls.some(([sev]) => sev === undefined)).toBe(true);
  });

  it("sin captura no hay mapa", async () => {
    api.capture.mockRejectedValue(Object.assign(new Error("x"), { status: 409 }));
    render(<App />);
    await screen.findByRole("button", { name: "Modo demo" });
    expect(screen.queryByRole("heading", { name: /Mapa MITRE/ })).toBeNull();
  });

  it("un fallo al pedir las alertas para el mapa sale en el banner", async () => {
    api.alerts.mockRejectedValue(new Error("alertas rotas"));
    render(<App />);
    expect(await screen.findByText(/alertas rotas/)).toBeInTheDocument();
  });

  it("cada tarjeta principal ofrece su botón de ayuda", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: /Mapa MITRE/ });
    for (const t of ["Resumen", "Alertas", "Sesiones", "Mapa MITRE", "Indicadores de compromiso"]) {
      expect(screen.getByRole("button", { name: new RegExp(`^Ayuda: ${t}`) })).toBeInTheDocument();
    }
  });
});
