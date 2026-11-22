import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { remoteAccess: vi.fn() } }));
import { api } from "../../api/client.js";
import RemoteAccessView from "./RemoteAccessView.jsx";

const item = (over = {}) => ({
  id: 1, service: "RDP", port: 3389, client_ip: "10.0.0.5", server_ip: "10.0.0.9", direction: "Interno→Interno (lateral)",
  packets: 4, bytes: 2048, first_ts: 1700000000, duration: 2, syn_packets: 2, syn_retries: 1, rst_packets: 1,
  signals: ["Con RST (1): conexión rechazada o cortada de golpe", "Reintentos de conexión: 1 SYN reenviado(s)"], ...over,
});
const group = (over = {}) => ({
  service: "RDP", ports: [3389], sessions: 1, clients: 1, servers: 1, with_rst: 1, retries: 1, bytes: 2048, truncated: false, items: [item()], ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.remoteAccess.mockResolvedValue({ total: 1, services: [group()] });
});

describe("RemoteAccessView", () => {
  it("muestra una tabla por servicio con RST, reintentos y señales", async () => {
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    const rdp = await screen.findByRole("region", { name: /RDP/ });
    expect(within(rdp).getByText("10.0.0.9:3389")).toBeInTheDocument();
    expect(within(rdp).getByText(/Con RST \(1\)/)).toBeInTheDocument();
    expect(within(rdp).getByText("Interno→Interno (lateral)")).toBeInTheDocument();
    expect(within(rdp).getByText(/1 con RST/)).toBeInTheDocument();
    expect(api.remoteAccess).toHaveBeenCalledWith(undefined, expect.any(AbortSignal));
  });

  it("agrupa varios servicios, cada uno con su título", async () => {
    api.remoteAccess.mockResolvedValue({
      total: 2, services: [group({ service: "SSH", ports: [22], items: [item({ service: "SSH", port: 22, id: 2 })] }), group()],
    });
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    expect(await screen.findByRole("heading", { name: /SSH/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /RDP/ })).toBeInTheDocument();
  });

  it("el filtro por servicio vuelve a pedir con ese servicio", async () => {
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    await screen.findByRole("region", { name: /RDP/ });
    await userEvent.selectOptions(screen.getByLabelText("Servicio"), "SSH");
    expect(api.remoteAccess).toHaveBeenLastCalledWith("SSH", expect.any(AbortSignal));
  });

  it("sin conexiones de acceso remoto lo dice", async () => {
    api.remoteAccess.mockResolvedValue({ total: 0, services: [] });
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    expect(await screen.findByText(/No hay conexiones de acceso remoto/)).toBeInTheDocument();
  });

  it("avisa cuando el detalle está acotado", async () => {
    api.remoteAccess.mockResolvedValue({ total: 300, services: [group({ truncated: true, sessions: 300 })] });
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    expect(await screen.findByRole("note")).toHaveTextContent("el resumen cuenta todas");
  });

  it("el cliente es un botón que filtra las sesiones por su IP", async () => {
    const onFilterIp = vi.fn();
    render(<RemoteAccessView refreshKey={0} onError={onError} onFilterIp={onFilterIp} />);
    await userEvent.click(await screen.findByRole("button", { name: "10.0.0.5" }));
    expect(onFilterIp).toHaveBeenCalledWith("10.0.0.5");
  });

  it("un error de la API se informa", async () => {
    api.remoteAccess.mockRejectedValue(new Error("409"));
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    await screen.findByText("Cargando…");
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("409"));
  });

  it("el texto de las señales no se interpreta como HTML", async () => {
    api.remoteAccess.mockResolvedValue({ total: 1, services: [group({ items: [item({ signals: ["<img src=x onerror=alert(1)>"] })] })] });
    render(<RemoteAccessView refreshKey={0} onError={onError} />);
    await screen.findByRole("region", { name: /RDP/ });
    expect(document.querySelector("img")).toBeNull();
  });
});
