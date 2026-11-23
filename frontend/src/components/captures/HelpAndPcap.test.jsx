import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({
  api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    alerts: vi.fn(), sessions: vi.fn(), sessionPackets: vi.fn(), packet: vi.fn(), stream: vi.fn(), iocs: vi.fn(), timeline: vi.fn(),
    loadIocs: vi.fn(), clearIocs: vi.fn(),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`),
  },
}));
import { api } from "../../api/client.js";
import AlertsTable from "./AlertsTable.jsx";
import IocPanel from "./IocPanel.jsx";
import SessionDetail from "./SessionDetail.jsx";
import SessionsTable from "./SessionsTable.jsx";
import StreamView from "./StreamView.jsx";
import Summary from "./Summary.jsx";
import Timeline from "./Timeline.jsx";

const alertOf = (over = {}) => ({
  rule_id: "R1", name: "Escaneo", severity: "high", mitre_technique: "T1046", mitre_name: "Scan", mitre_tactic: "Discovery",
  description: "d", src_ip: "192.168.1.66", dst_ip: "10.0.0.9", first_ts: 1700000000, evidence: { a: 1 }, ...over,
});
const session = { id: 7, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1, dst_ip: "10.0.0.2", dst_port: 80, packets: 3, bytes: 99 };
const summary = {
  source: "x.pcap", format: "pcap", linktype: 1, snaplen: 65535, alerts: 0, rules: 8,
  stats: { sessions: 1, packets: 1, bytes: 1, by_protocol: {}, non_ip: 0, malformed: 0 },
};

beforeEach(() => {
  vi.clearAllMocks();
  api.alerts.mockResolvedValue([alertOf(), alertOf({ rule_id: "R2", name: "Otra", src_ip: "10.1.1.1" })]);
  api.sessions.mockResolvedValue({ total: 1, items: [{ ...session, first_ts: 1, last_ts: 2, duration: 1 }] });
  api.sessionPackets.mockResolvedValue({ items: [{ index: 3, ts: 1, caplen: 60, origlen: 60, snaplen_limited: false }], has_more: false });
  api.packet.mockResolvedValue({
    index: 3, ts: 1, caplen: 60, origlen: 60, snaplen_limited: false, session_id: 7, endpoints: null, hexdump: "x",
    layers: [{ name: "Ethernet", start: 0, end: 14, note: null, fields: [] }],
  });
  api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
  api.timeline.mockResolvedValue({ start: 1700000000, bucket_seconds: 1, packets: [1, 2], bytes: [1, 2] });
});

describe("botones de ayuda en las cabeceras", () => {
  it.each([
    ["Summary", () => render(<Summary capture={summary} />), "Resumen"],
    ["Timeline", () => render(<Timeline refreshKey={0} onError={() => {}} />), "Tráfico en el tiempo"],
    ["AlertsTable", () => render(<AlertsTable refreshKey={0} onError={() => {}} />), "Alertas"],
    ["IocPanel", () => render(<IocPanel onChange={() => {}} onError={() => {}} />), "Indicadores de compromiso"],
    [
      "SessionsTable",
      () => render(<SessionsTable refreshKey={0} filters={{ protocol: "", ip: "", port: "" }} onFilters={() => {}} selectedId={null} onSelect={() => {}} />),
      "Sesiones",
    ],
    ["StreamView", () => render(<StreamView session={session} onError={() => {}} />), "Conversación"],
  ])("%s tiene su HelpTip y al abrirlo muestra una nota", async (_n, draw, title) => {
    const { container } = draw();
    const btn = await screen.findByRole("button", { name: new RegExp(`^Ayuda: ${title}`) });
    expect(btn.closest(".head-title, h3, .card-head, section")).not.toBeNull();
    await userEvent.click(btn);
    expect(screen.getByRole("note").textContent.length).toBeGreaterThan(20);
    expect(container.querySelectorAll(".help-btn")).toHaveLength(1);
  });

  it("las cabeceras con HelpTip no ensucian el nombre del <h2> (el botón queda fuera)", async () => {
    render(<Summary capture={summary} />);
    expect(screen.getByRole("heading", { name: "Resumen" })).toBeInTheDocument();
  });

  it("SessionsTable envuelve el título en div.head-title", async () => {
    const { container } = render(
      <SessionsTable refreshKey={0} filters={{ protocol: "", ip: "", port: "" }} onFilters={() => {}} selectedId={null} onSelect={() => {}} />,
    );
    await screen.findByRole("button", { name: /Ver paquetes/ });
    const wrap = container.querySelector(".head-title");
    expect(wrap.querySelector("#sessions-title")).not.toBeNull();
    expect(wrap.querySelector(".help-btn")).not.toBeNull();
  });
});

describe("SessionDetail: ayudas y descarga de .pcap", () => {
  it("ayudas de Capas y de Paquete, y la de .pcap", async () => {
    render(<SessionDetail session={session} onClose={() => {}} onError={() => {}} />);
    await screen.findByLabelText("Volcado hexadecimal");
    expect(screen.getByRole("button", { name: /Ayuda: Capas/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ayuda: Volcado hexadecimal/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ayuda: Descargar \.pcap/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ayuda: Conversación/ })).toBeInTheDocument();
  });

  it("enlace 'Descargar .pcap de esta sesión' con la URL de la API y el atributo download", async () => {
    render(<SessionDetail session={session} onClose={() => {}} onError={() => {}} />);
    const a = await screen.findByRole("link", { name: "Descargar .pcap de esta sesión" });
    expect(a).toHaveAttribute("href", "/api/sessions/7/pcap");
    expect(a).toHaveAttribute("download", "tracewell-sesion-7.pcap");
    expect(api.sessionPcapUrl).toHaveBeenCalledWith(7);
  });

  it("al cambiar de sesión el enlace apunta a la nueva", async () => {
    const { rerender } = render(<SessionDetail session={session} onClose={() => {}} onError={() => {}} />);
    await screen.findByRole("link", { name: "Descargar .pcap de esta sesión" });
    rerender(<SessionDetail session={{ ...session, id: 12 }} onClose={() => {}} onError={() => {}} />);
    const a = await screen.findByRole("link", { name: "Descargar .pcap de esta sesión" });
    expect(a).toHaveAttribute("href", "/api/sessions/12/pcap");
    expect(a).toHaveAttribute("download", "tracewell-sesion-12.pcap");
  });

  it("la sección Capas no aparece si el paquete no trae capas, y la ayuda de Capas tampoco", async () => {
    api.packet.mockResolvedValue({ index: 3, ts: 1, caplen: 60, origlen: 60, snaplen_limited: false, session_id: 7, endpoints: null, hexdump: "x" });
    render(<SessionDetail session={session} onClose={() => {}} onError={() => {}} />);
    await screen.findByLabelText("Volcado hexadecimal");
    expect(screen.queryByRole("button", { name: /Ayuda: Capas/ })).toBeNull();
  });
});

describe("AlertsTable: descargar .pcap de la IP", () => {
  const open = async (onViewSessions = vi.fn()) => {
    render(<AlertsTable refreshKey={0} onError={() => {}} onViewSessions={onViewSessions} />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
  };

  it("la alerta expandida trae un enlace con filteredPcapUrl({ip}) y download", async () => {
    await open();
    const a = screen.getByRole("link", { name: "Descargar .pcap de 192.168.1.66" });
    expect(a).toHaveAttribute("href", "/api/pcap?ip=192.168.1.66");
    expect(a).toHaveAttribute("download");
    expect(api.filteredPcapUrl).toHaveBeenCalledWith({ ip: "192.168.1.66" });
  });

  it("solo la alerta expandida muestra el enlace, y cada una usa su IP", async () => {
    await open();
    expect(screen.getAllByRole("link", { name: /Descargar \.pcap/ })).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: /Otra/ }));
    const only = screen.getAllByRole("link", { name: /Descargar \.pcap/ });
    expect(only).toHaveLength(1);
    expect(only[0]).toHaveAttribute("href", "/api/pcap?ip=10.1.1.1");
  });

  it("sin onViewSessions (sin acciones) no hay enlace", async () => {
    render(<AlertsTable refreshKey={0} onError={() => {}} />);
    await userEvent.click(await screen.findByRole("button", { name: /Escaneo/ }));
    expect(screen.queryByRole("link", { name: /Descargar/ })).toBeNull();
  });

  it("una IP con HTML se muestra como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.alerts.mockResolvedValue([alertOf({ src_ip: evil })]);
    await open();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByRole("link", { name: `Descargar .pcap de ${evil}` })).toBeInTheDocument();
  });
});
