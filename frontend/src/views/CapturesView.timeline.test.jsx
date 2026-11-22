import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const chart = vi.hoisted(() => ({ props: null }));
vi.mock("@mantine/charts", () => ({
  BarChart: (props) => {
    chart.props = props;
    return <div data-testid="bar-chart" />;
  },
}));

vi.mock("../api/client.js", () => ({
  api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    caseTimeline: vi.fn(() => Promise.resolve({ host: null, total: 0, truncated: false, items: [] })), remoteAccess: vi.fn(() => Promise.resolve({ total: 0, services: [] })), httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`),
    demo: vi.fn(), analyze: vi.fn(), capture: vi.fn(), sessions: vi.fn(), alerts: vi.fn(), timeline: vi.fn(),
    sessionPackets: vi.fn(), packet: vi.fn(), interfaces: vi.fn(), liveStart: vi.fn(),
    liveStatus: vi.fn(), liveStop: vi.fn(), exportUrl: vi.fn(() => "/api/export"),
    iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn(), saveNote: vi.fn(), reportUrl: vi.fn(() => "/api/report"),
  },
}));
import { api } from "../api/client.js";
import App from "./CapturesView.jsx";

const summary = {
  source: "demo.pcap", format: "pcap", linktype: 1, snaplen: 65535, alerts: 0, rules: 8,
  stats: { sessions: 0, packets: 3, bytes: 30, by_protocol: {}, non_ip: 0, malformed: 0 },
};

beforeEach(() => {
  vi.clearAllMocks();
  api.alerts.mockResolvedValue([]);
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
  api.sessions.mockResolvedValue({ total: 0, items: [] });
  api.timeline.mockResolvedValue({ start: 1700000000, bucket_seconds: 1, packets: [1, 2, 3], bytes: [10, 20, 30] });
});

describe("App y el gráfico de tráfico", () => {
  it("con una captura cargada muestra el gráfico justo después del Resumen", async () => {
    api.capture.mockResolvedValue(summary);
    render(<App />);
    const graph = await screen.findByRole("img", { name: /Tráfico en el tiempo/ });
    const resumen = screen.getByRole("heading", { name: "Resumen" });
    const titulo = screen.getByRole("heading", { name: "Tráfico en el tiempo" });
    expect(resumen.compareDocumentPosition(titulo) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Alertas" }).compareDocumentPosition(titulo) & Node.DOCUMENT_POSITION_PRECEDING).toBeTruthy();
    expect(graph.querySelector("[data-testid=bar-chart]")).not.toBeNull();
    expect(chart.props.data).toHaveLength(3);
  });

  it("sin captura (409) no se pide la línea de tiempo", async () => {
    api.capture.mockRejectedValue(Object.assign(new Error("No hay captura"), { status: 409 }));
    render(<App />);
    await screen.findByRole("button", { name: /demo/i });
    expect(api.timeline).not.toHaveBeenCalled();
    expect(screen.queryByRole("heading", { name: "Tráfico en el tiempo" })).toBeNull();
  });

  it("una captura sin paquetes (arreglos vacíos) no muestra el gráfico", async () => {
    api.capture.mockResolvedValue(summary);
    api.timeline.mockResolvedValue({ start: 0, bucket_seconds: 1, packets: [], bytes: [] });
    render(<App />);
    await screen.findByRole("heading", { name: "Resumen" });
    await waitFor(() => expect(api.timeline).toHaveBeenCalled());
    expect(screen.queryByRole("heading", { name: "Tráfico en el tiempo" })).toBeNull();
  });

  it("un fallo del endpoint se muestra en el banner de error", async () => {
    api.capture.mockResolvedValue(summary);
    api.timeline.mockRejectedValue(new Error("timeline roto"));
    render(<App />);
    expect(await screen.findByText(/timeline roto/)).toBeInTheDocument();
  });
});
