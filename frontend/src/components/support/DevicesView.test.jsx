import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { supportDevices: vi.fn() } }));
import { api } from "../../api/client.js";
import DevicesView from "./DevicesView.jsx";

const dev = (over = {}) => ({ ip: "192.168.1.5", mac: "aa:bb:cc:00:11:22", vendor: "Acme", random_mac: false, hostname: "impresora", is_gateway: false, is_self: false, ...over });
const res = (devices, over = {}) => ({ devices, scanned: false, swept_hosts: 0, subnets: ["192.168.1.0/24"], vendor_db: true, ...over });
const rows = (c) => Array.from(c.querySelectorAll("tbody tr"));

beforeEach(() => {
  vi.clearAllMocks();
  api.supportDevices.mockResolvedValue(res([dev()]));
});

describe("DevicesView", () => {
  it("al montar pide scan=false (sin barrido) y muestra la tabla", async () => {
    const { container } = render(<DevicesView />);
    expect(await screen.findByText("impresora")).toBeInTheDocument();
    expect(api.supportDevices).toHaveBeenCalledTimes(1);
    expect(api.supportDevices.mock.calls[0][0]).toBe(false);
    expect(rows(container)).toHaveLength(1);
    expect(screen.getByText("1 dispositivos · red 192.168.1.0/24")).toBeInTheDocument();
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("«Buscar en la red» pide scan=true; «Ver lo que ya conoce» vuelve a false", async () => {
    render(<DevicesView />);
    await screen.findByText("impresora");
    await userEvent.click(screen.getByRole("button", { name: "Buscar en la red" }));
    await waitFor(() => expect(api.supportDevices).toHaveBeenCalledTimes(2));
    expect(api.supportDevices.mock.calls[1][0]).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: "Ver lo que ya conoce mi PC" }));
    await waitFor(() => expect(api.supportDevices).toHaveBeenCalledTimes(3));
    expect(api.supportDevices.mock.calls[2][0]).toBe(false);
  });

  it("banner si no hay base de fabricantes", async () => {
    api.supportDevices.mockResolvedValue(res([dev({ vendor: null })], { vendor_db: false }));
    render(<DevicesView />);
    expect(await screen.findByRole("note")).toHaveTextContent("oui.csv");
  });

  it("MAC aleatoria, marca desconocida, y pills router / esta PC", async () => {
    api.supportDevices.mockResolvedValue(res([
      dev({ ip: "192.168.1.1", is_gateway: true, hostname: null }),
      dev({ ip: "192.168.1.9", mac: "da:a1:19:00:00:01", vendor: null, random_mac: true }),
      dev({ ip: "192.168.1.10", vendor: null, is_self: true, hostname: "MI-PC" }),
    ]));
    const { container } = render(<DevicesView />);
    await screen.findByText("MI-PC");
    const r = rows(container);
    expect(r[0]).toHaveTextContent("router");
    expect(r[0]).not.toHaveTextContent("esta PC");
    expect(r[1]).toHaveTextContent("MAC privada (aleatoria)");
    expect(r[2]).toHaveTextContent("esta PC");
    expect(r[2]).toHaveTextContent("desconocida");
  });

  it("sin dispositivos: mensaje; error de la API: alerta", async () => {
    api.supportDevices.mockResolvedValue(res([]));
    const { unmount } = render(<DevicesView />);
    expect(await screen.findByText(/Todavía no hay vecinos conocidos/)).toBeInTheDocument();
    unmount();
    api.supportDevices.mockRejectedValue(new Error("sin psutil"));
    render(<DevicesView />);
    expect(await screen.findByRole("alert")).toHaveTextContent("sin psutil");
  });

  it("nombres y marcas hostiles se ven como texto", async () => {
    const evil = "<script>window.__z=1</script>";
    api.supportDevices.mockResolvedValue(res([dev({ hostname: evil, vendor: "<b>x</b>" })]));
    const { container } = render(<DevicesView />);
    await screen.findByText(evil);
    expect(container.querySelector("script, b")).toBeNull();
    expect(container.textContent).toContain("<b>x</b>");
  });
});
