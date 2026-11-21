import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

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

const session = {
  id: 7,
  protocol: "TCP",
  src_ip: "10.0.0.1",
  src_port: 1234,
  dst_ip: "10.0.0.2",
  dst_port: 80,
  packets: 3,
  bytes: 4096,
};
const pk = (index, over = {}) => ({ index, ts: 1700000000 + index, caplen: 60, origlen: 60, snaplen_limited: false, ...over });
const detail = (index, over = {}) => ({
  ...pk(index),
  session_id: 7,
  endpoints: { protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80 },
  hexdump: `dump-${index}`,
  ...over,
});

let onClose, onError;
beforeEach(() => {
  vi.clearAllMocks();
  onClose = vi.fn();
  onError = vi.fn();
  api.sessionPackets.mockResolvedValue({ items: [pk(10), pk(11)], has_more: false });
  api.packet.mockImplementation(async (i) => detail(i));
});

const renderIt = () => render(<SessionDetail session={session} onClose={onClose} onError={onError} />);

describe("SessionDetail", () => {
  it("carga paquetes, selecciona el primero y muestra su hexdump", async () => {
    renderIt();
    expect(await screen.findByLabelText("Volcado hexadecimal")).toHaveTextContent("dump-10");
    expect(api.sessionPackets).toHaveBeenCalledWith(7, { limit: 50, offset: 0 });
    expect(screen.getByRole("button", { name: /#10/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /#11/ })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByText("Sesión 7")).toBeInTheDocument();
    expect(screen.getAllByText(/10.0.0.1:1234/).length).toBeGreaterThanOrEqual(1);
  });

  it("cambia de paquete", async () => {
    renderIt();
    await screen.findByText("dump-10");
    await userEvent.click(screen.getByRole("button", { name: /#11/ }));
    expect(await screen.findByText("dump-11")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /#11/ })).toHaveAttribute("aria-pressed", "true");
    expect(api.packet).toHaveBeenLastCalledWith(11, expect.any(AbortSignal));
  });

  it("'Cargar más' solo si has_more, y pide el offset siguiente sin perder lo cargado", async () => {
    api.sessionPackets
      .mockResolvedValueOnce({ items: [pk(10), pk(11)], has_more: true })
      .mockResolvedValueOnce({ items: [pk(12)], has_more: false });
    renderIt();
    const more = await screen.findByRole("button", { name: "Cargar más" });
    await userEvent.click(more);
    expect(await screen.findByRole("button", { name: /#12/ })).toBeInTheDocument();
    expect(api.sessionPackets).toHaveBeenLastCalledWith(7, { limit: 50, offset: 2 });
    expect(screen.getByRole("button", { name: /#10/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cargar más" })).toBeNull();
    // "cargar más" no cambia el paquete seleccionado
    expect(screen.getByRole("button", { name: /#10/ })).toHaveAttribute("aria-pressed", "true");
  });

  it("sin has_more no hay 'Cargar más'", async () => {
    renderIt();
    await screen.findByText("dump-10");
    expect(screen.queryByRole("button", { name: "Cargar más" })).toBeNull();
  });

  it("avisa cuando el paquete fue recortado por snaplen", async () => {
    api.sessionPackets.mockResolvedValue({ items: [pk(10, { snaplen_limited: true })], has_more: false });
    api.packet.mockResolvedValue(detail(10, { snaplen_limited: true, origlen: 1500, caplen: 96 }));
    renderIt();
    expect(await screen.findByRole("note")).toHaveTextContent(/recortado por snaplen/i);
    expect(screen.getByText("recortado")).toBeInTheDocument();
    expect(screen.getByText(/96 B capturados de 1500 B/)).toBeInTheDocument();
  });

  it("sin recorte no muestra el aviso", async () => {
    renderIt();
    await screen.findByText("dump-10");
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("hexdump con HTML hostil se muestra como texto", async () => {
    const evil = "<img src=x onerror=alert(1)><script>alert(2)</script>";
    api.packet.mockResolvedValue(detail(10, { hexdump: evil }));
    const { container } = renderIt();
    const pre = await screen.findByLabelText("Volcado hexadecimal");
    expect(pre.textContent).toBe(evil);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
  });

  it("hexdump vacío -> '(sin datos)'", async () => {
    api.packet.mockResolvedValue(detail(10, { hexdump: "" }));
    renderIt();
    expect(await screen.findByText("(sin datos)")).toBeInTheDocument();
  });

  it("cerrar llama onClose", async () => {
    renderIt();
    await screen.findByText("dump-10");
    await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("error al cargar paquetes -> onError", async () => {
    api.sessionPackets.mockRejectedValue(new Error("sesión inexistente"));
    renderIt();
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("sesión inexistente"));
  });

  it("error al cargar un paquete -> onError", async () => {
    api.packet.mockRejectedValue(new Error("paquete inexistente"));
    renderIt();
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("paquete inexistente"));
  });

  it("al cambiar de sesión recarga y reselecciona el primer paquete", async () => {
    const { rerender } = renderIt();
    await screen.findByText("dump-10");
    api.sessionPackets.mockResolvedValue({ items: [pk(20)], has_more: false });
    rerender(<SessionDetail session={{ ...session, id: 8 }} onClose={onClose} onError={onError} />);
    expect(await screen.findByText("dump-20")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /#10/ })).toBeNull();
  });
});
