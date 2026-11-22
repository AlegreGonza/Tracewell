import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api/client.js", () => ({
  api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    remoteAccess: vi.fn(() => Promise.resolve({ total: 0, services: [] })), httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`),
    demo: vi.fn(), analyze: vi.fn(), capture: vi.fn(), sessions: vi.fn(), alerts: vi.fn(), timeline: vi.fn(),
    sessionPackets: vi.fn(), packet: vi.fn(), stream: vi.fn(), interfaces: vi.fn(), liveStart: vi.fn(),
    liveStatus: vi.fn(), liveStop: vi.fn(), exportUrl: vi.fn(() => "/api/export"), closeCapture: vi.fn(),
    iocs: vi.fn(), loadIocs: vi.fn(), clearIocs: vi.fn(), saveNote: vi.fn(), reportUrl: vi.fn(() => "/api/report"),
  },
}));
import { api } from "../api/client.js";
import App from "./CapturesView.jsx";

const summary = (source) => ({
  source, format: "pcap", linktype: 1, snaplen: 65535, alerts: 0, rules: 8,
  stats: { sessions: 1, packets: 1, bytes: 1, by_protocol: {}, non_ip: 0, malformed: 0 },
});
const conflict = () => Object.assign(new Error("No hay captura"), { status: 409 });

beforeEach(() => {
  vi.clearAllMocks();
  api.capture.mockRejectedValue(conflict());
  api.alerts.mockResolvedValue([]);
  api.interfaces.mockResolvedValue([]);
  api.iocs.mockResolvedValue({ loaded: false, source: null, ips: 0, networks: 0, domains: 0, sessions: 0 });
  api.timeline.mockResolvedValue({ start: 0, bucket_seconds: 1, packets: [], bytes: [] });
  api.sessions.mockResolvedValue({
    total: 1,
    items: [{ id: 1, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1, dst_ip: "10.0.0.2", dst_port: 2, packets: 1, bytes: 1, first_ts: 1, last_ts: 2, duration: 1 }],
  });
  api.sessionPackets.mockResolvedValue({ items: [], has_more: false });
  api.closeCapture.mockResolvedValue({ cleared: true });
});

const loadDemo = async () => {
  api.demo.mockResolvedValue(summary("demo.pcap"));
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "Modo demo" }));
  await screen.findByRole("heading", { name: "Resumen" });
};
const loadFile = async () => {
  api.analyze.mockResolvedValue(summary("a.pcap"));
  render(<App />);
  await userEvent.type(await screen.findByLabelText(/Ruta del archivo/), "a.pcap");
  await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
  await screen.findByRole("heading", { name: "Resumen" });
};

describe("App: cerrar captura", () => {
  it("sin captura no hay botón de cerrar", async () => {
    render(<App />);
    await screen.findByRole("button", { name: "Modo demo" });
    expect(screen.queryByRole("button", { name: /Salir del demo|Cerrar captura/ })).toBeNull();
  });

  it("con el demo el botón dice 'Salir del demo'", async () => {
    await loadDemo();
    expect(screen.getByRole("button", { name: "Salir del demo" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cerrar captura" })).toBeNull();
  });

  it("con otro archivo dice 'Cerrar captura'", async () => {
    await loadFile();
    expect(screen.getByRole("button", { name: "Cerrar captura" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Salir del demo" })).toBeNull();
  });

  it("un clic llama a api.closeCapture, vuelve a la bienvenida y no pide nada más solo", async () => {
    await loadDemo();
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    expect(await screen.findByRole("button", { name: "Modo demo" })).toBeInTheDocument();
    expect(api.closeCapture).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("heading", { name: "Resumen" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Salir del demo|Cerrar captura/ })).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("limpia filtros y selección: al volver a cargar no queda nada seleccionado ni filtrado", async () => {
    await loadFile();
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    expect(await screen.findByRole("heading", { name: "Sesión 1" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cerrar captura" }));
    await screen.findByRole("button", { name: "Modo demo" });
    expect(screen.queryByRole("heading", { name: "Sesión 1" })).toBeNull();
    api.demo.mockResolvedValue(summary("demo.pcap"));
    await userEvent.click(screen.getByRole("button", { name: "Modo demo" }));
    await screen.findByRole("heading", { name: "Resumen" });
    expect(screen.queryByRole("heading", { name: "Sesión 1" })).toBeNull();
    expect(api.sessions).toHaveBeenLastCalledWith(expect.objectContaining({ protocol: "", ip: "", port: "" }), expect.anything());
  });

  it("borra el error anterior al cerrar con éxito", async () => {
    await loadDemo();
    api.analyze.mockRejectedValue(new Error("archivo roto"));
    await userEvent.type(document.getElementById("path"), "x.pcap");
    await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
    expect(await screen.findByText(/archivo roto/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    await screen.findByRole("button", { name: "Modo demo" });
    expect(screen.queryByText(/archivo roto/)).toBeNull();
  });

  it("mientras cierra el botón está deshabilitado (busy)", async () => {
    await loadDemo();
    let resolve;
    api.closeCapture.mockReturnValue(new Promise((r) => (resolve = r)));
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    expect(screen.getByRole("button", { name: "Salir del demo" })).toBeDisabled();
    resolve({ cleared: true });
    expect(await screen.findByRole("button", { name: "Modo demo" })).toBeInTheDocument();
  });

  it("si el servidor falla: banner de error y el análisis se conserva", async () => {
    await loadDemo();
    api.closeCapture.mockRejectedValue(new Error("no se pudo cerrar"));
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    expect(await screen.findByText(/no se pudo cerrar/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Resumen" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Salir del demo" })).toBeEnabled());
    // y se puede reintentar
    api.closeCapture.mockResolvedValue({ cleared: true });
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    expect(await screen.findByRole("button", { name: "Modo demo" })).toBeInTheDocument();
    expect(api.closeCapture).toHaveBeenCalledTimes(2);
  });

  it("al recargar tras cerrar el servidor responde 409 y se ve la bienvenida", async () => {
    await loadDemo();
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    await screen.findByRole("button", { name: "Modo demo" });
    document.body.innerHTML = "";
    render(<App />); // "recarga": una App nueva consulta al servidor, que ya no tiene captura
    expect(await screen.findByRole("button", { name: "Modo demo" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Resumen" })).toBeNull();
  });

  it("se puede cargar otra captura después de cerrar", async () => {
    await loadDemo();
    await userEvent.click(screen.getByRole("button", { name: "Salir del demo" }));
    await screen.findByRole("button", { name: "Modo demo" });
    api.analyze.mockResolvedValue(summary("b.pcap"));
    await userEvent.type(screen.getByLabelText(/Ruta del archivo/), "b.pcap");
    await userEvent.click(screen.getByRole("button", { name: "Analizar" }));
    expect(await screen.findByRole("button", { name: "Cerrar captura" })).toBeInTheDocument();
  });
});
