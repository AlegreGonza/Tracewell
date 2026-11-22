import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

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

const summary = (processes) => ({
  source: "live.pcap", format: "pcap", linktype: 1, snaplen: 65535, alerts: 0, rules: 1,
  stats: { sessions: 1, packets: 1, bytes: 1, by_protocol: {}, non_ip: 0, malformed: 0 },
  ...(processes === undefined ? {} : { processes }),
});

beforeEach(() => {
  vi.clearAllMocks();
  api.timeline.mockResolvedValue({ start: 0, bucket_seconds: 1, packets: [], bytes: [] });
  api.alerts.mockResolvedValue([]);
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
  api.sessions.mockResolvedValue({
    total: 1,
    items: [{ id: 1, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1, dst_ip: "10.0.0.2", dst_port: 2,
      packets: 1, bytes: 1, first_ts: 1, last_ts: 2, duration: 1, process: { pid: 5, name: "firefox.exe" } }],
  });
});

describe("App y la columna Proceso", () => {
  it("processes true -> columna visible", async () => {
    api.capture.mockResolvedValue(summary(true));
    render(<App />);
    expect(await screen.findByRole("columnheader", { name: "Proceso" })).toBeInTheDocument();
    expect(await screen.findByText("firefox.exe")).toBeInTheDocument();
  });

  it.each([[false], [undefined], ["true"], [1]])("processes=%s -> sin columna", async (v) => {
    api.capture.mockResolvedValue(summary(v));
    render(<App />);
    await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" });
    expect(screen.queryByRole("columnheader", { name: "Proceso" })).toBeNull();
  });
});
