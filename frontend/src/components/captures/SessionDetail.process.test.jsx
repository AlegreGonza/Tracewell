import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({ api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`), sessionPackets: vi.fn(), packet: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionDetail from "./SessionDetail.jsx";

const base = { id: 7, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1, dst_ip: "10.0.0.2", dst_port: 80, packets: 3, bytes: 4096 };

beforeEach(() => {
  vi.clearAllMocks();
  api.sessionPackets.mockResolvedValue({ items: [], has_more: false });
  api.packet.mockResolvedValue({});
});
const show = (session) => render(<SessionDetail session={session} onClose={() => {}} onError={() => {}} />);

describe("SessionDetail proceso", () => {
  it("sin clave process no muestra la línea", async () => {
    show(base);
    await screen.findByText("Sesión 7");
    expect(screen.queryByText(/Proceso:/)).toBeNull();
  });

  it("con proceso muestra nombre y PID", async () => {
    show({ ...base, process: { pid: 99, name: "curl.exe" } });
    const line = (await screen.findByText(/Proceso:/)).closest("p");
    expect(line).toHaveTextContent("Proceso: curl.exe (PID 99)");
  });

  it("process null muestra 'no identificado'", async () => {
    show({ ...base, process: null });
    expect(await screen.findByText("no identificado")).toBeInTheDocument();
    expect(screen.getByText(/Proceso:/)).toBeInTheDocument();
  });

  it("nombre hostil como texto", async () => {
    const hostile = "<img src=x onerror=alert(1)>";
    const { container } = show({ ...base, process: { pid: 1, name: hostile } });
    expect(await screen.findByText(hostile)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
