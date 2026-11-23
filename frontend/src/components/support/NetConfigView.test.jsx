import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { supportConfig: vi.fn(), supportConfigRaw: vi.fn() } }));
import { api } from "../../api/client.js";
import NetConfigView from "./NetConfigView.jsx";

const adapter = (over = {}) => ({
  name: "Ethernet", description: "Intel NIC", up: true, speed_mbps: 1000, mtu: 1500, mac: "AA:BB:CC:00:11:22",
  ipv4: [{ ip: "192.168.1.10", mask: "255.255.255.0" }], ipv6: ["fe80::1"], gateway: ["192.168.1.1"], dns: ["1.1.1.1", "8.8.8.8"], dhcp: true, apipa: false, loopback: false, ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  api.supportConfig.mockResolvedValue({ hostname: "MI-PC", adapters: [adapter()] });
  api.supportConfigRaw.mockResolvedValue({ available: true, command: "ipconfig /all", text: "Configuración IP de Windows\n  Nombre: MI-PC" });
});

describe("NetConfigView", () => {
  it("muestra el adaptador con IP, puerta de enlace, DNS y DHCP", async () => {
    render(<NetConfigView active />);
    expect(await screen.findByRole("heading", { name: /Ethernet/ })).toBeInTheDocument();
    expect(screen.getByText("MI-PC")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.10 / 255.255.255.0")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
    expect(screen.getByText("1.1.1.1, 8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("Sí")).toBeInTheDocument();
    expect(screen.getByText("conectado")).toBeInTheDocument();
    expect(screen.queryByRole("note", { name: "" })).not.toBeInTheDocument();
  });

  it("IP fija y valores vacíos con raya", async () => {
    api.supportConfig.mockResolvedValue({ hostname: "h", adapters: [adapter({ dhcp: false, gateway: [], dns: [], description: null, up: false })] });
    render(<NetConfigView active />);
    expect(await screen.findByText("No: IP fija")).toBeInTheDocument();
    expect(screen.getByText("desconectado")).toBeInTheDocument();
  });

  it("banner de IP 169.254 (APIPA) solo cuando corresponde", async () => {
    api.supportConfig.mockResolvedValue({ hostname: "h", adapters: [adapter({ name: "Wi-Fi", apipa: true, ipv4: [{ ip: "169.254.9.9", mask: "255.255.0.0" }] }), adapter()] });
    render(<NetConfigView active />);
    await screen.findByText(/Equipo:/);
    expect(screen.getAllByRole("note")).toHaveLength(1);
    expect(screen.getByRole("note")).toHaveTextContent("169.254.x.x");
  });

  it("la salida completa NO se pide hasta abrir el <details>", async () => {
    const { container } = render(<NetConfigView active />);
    await screen.findByText(/Equipo:/);
    expect(api.supportConfigRaw).not.toHaveBeenCalled();
    await userEvent.click(screen.getByText("Ver la salida completa del sistema"));
    expect(container.querySelector("details").open).toBe(true);
    await waitFor(() => expect(api.supportConfigRaw).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Configuración IP de Windows/)).toBeInTheDocument();
    expect(screen.getByText("ipconfig /all")).toBeInTheDocument();
    // cerrar y volver a abrir no vuelve a pedirla
    await userEvent.click(screen.getByText("Ver la salida completa del sistema"));
    await userEvent.click(screen.getByText("Ver la salida completa del sistema"));
    expect(api.supportConfigRaw).toHaveBeenCalledTimes(1);
  });

  it("salida no disponible muestra la razón; error de la API se avisa", async () => {
    api.supportConfigRaw.mockResolvedValue({ available: false, reason: "No se encontró el comando ipconfig." });
    render(<NetConfigView active />);
    await screen.findByText(/Equipo:/);
    await userEvent.click(screen.getByText("Ver la salida completa del sistema"));
    expect(await screen.findByText("No se encontró el comando ipconfig.")).toBeInTheDocument();
  });

  it("error al leer la configuración", async () => {
    api.supportConfig.mockRejectedValue(new Error("Falta psutil"));
    render(<NetConfigView active />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Falta psutil");
  });

  it("Actualizar vuelve a pedir y muestra la hora", async () => {
    render(<NetConfigView active />);
    await screen.findByText(/Equipo:/);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/Actualizado/));
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    await waitFor(() => expect(api.supportConfig).toHaveBeenCalledTimes(2));
  });

  it("datos hostiles se ven como texto, no como HTML", async () => {
    const evil = "<script>window.__x=1</script>";
    api.supportConfig.mockResolvedValue({ hostname: evil, adapters: [adapter({ name: `<img src=x onerror=alert(1)>`, description: evil })] });
    const { container } = render(<NetConfigView active />);
    await screen.findByText(/Equipo:/);
    expect(container.querySelector("script, img")).toBeNull();
    expect(container.textContent).toContain(evil);
    expect(window.__x).toBeUndefined();
  });

  it("no hay botones que modifiquen la red", async () => {
    render(<NetConfigView active />);
    await screen.findByText(/Equipo:/);
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/renovar|liberar|limpiar|flush|release|renew|cambiar/i);
  });
});
