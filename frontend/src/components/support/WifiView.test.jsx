import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { supportWifi: vi.fn(), supportWifiHistory: vi.fn() } }));
import { api } from "../../api/client.js";
import WifiView from "./WifiView.jsx";
import { Meter } from "./SystemOverview.jsx";

const wifi = (over = {}) => ({
  available: true, connected: true, quality: "buena", signal: 82, ssid: "MiRed", channel: 36, band: "5 GHz", radio: "802.11ac", auth: "WPA2-Personal",
  rx: 433, tx: 390, bssid: "aa:bb:cc:dd:ee:ff", ...over,
});
const hist = (events) => ({ available: true, events, disconnections: events.filter((e) => e.kind === "desconectado").length });

beforeEach(() => {
  vi.clearAllMocks();
  api.supportWifi.mockResolvedValue(wifi());
  api.supportWifiHistory.mockResolvedValue(hist([{ time: "2026-01-01T10:00:00", kind: "desconectado", message: "Se desconectó" }, { time: "2026-01-01T09:00:00", kind: "conectado", message: "Se conectó" }]));
});

describe("Meter goodHigh", () => {
  const level = (c) => c.querySelector(".meter").className;
  it("por defecto un valor alto es malo", () => {
    expect(level(render(<Meter label="x" percent={95} />).container)).toContain("meter-high");
  });
  it("con goodHigh se invierte: alto es bueno, bajo es malo", () => {
    expect(level(render(<Meter goodHigh label="x" percent={95} />).container)).toContain("meter-ok");
    expect(level(render(<Meter goodHigh label="x" percent={55} />).container)).toContain("meter-mid");
    expect(level(render(<Meter goodHigh label="x" percent={20} />).container)).toContain("meter-high");
  });
  it("umbrales de goodHigh: 40 y 70", () => {
    expect(level(render(<Meter goodHigh label="x" percent={39.9} />).container)).toContain("meter-high");
    expect(level(render(<Meter goodHigh label="x" percent={40} />).container)).toContain("meter-mid");
    expect(level(render(<Meter goodHigh label="x" percent={70} />).container)).toContain("meter-ok");
  });
});

describe("WifiView", () => {
  it("muestra señal con calidad, SSID, canal y velocidades", async () => {
    render(<WifiView active />);
    expect(await screen.findByText("MiRed")).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: "Señal (buena)" })).toHaveAttribute("aria-valuenow", "82");
    expect(screen.getByRole("meter").className).toContain("meter-ok");
    expect(screen.getByText("36 / 5 GHz")).toBeInTheDocument();
    expect(screen.getByText("433 Mbps / 390 Mbps")).toBeInTheDocument();
    expect(screen.queryByText(/acercate al router/)).not.toBeInTheDocument();
  });

  it("señal débil: medidor en rojo y consejo", async () => {
    api.supportWifi.mockResolvedValue(wifi({ signal: 25, quality: "débil" }));
    render(<WifiView active />);
    expect(await screen.findByText(/acercate al router/)).toBeInTheDocument();
    expect(screen.getByRole("meter").className).toContain("meter-high");
  });

  it("no disponible: muestra la razón; sin conexión: aviso", async () => {
    api.supportWifi.mockResolvedValue({ available: false, reason: "No hay un adaptador Wi-Fi activo." });
    const { unmount } = render(<WifiView active />);
    expect(await screen.findByText("No hay un adaptador Wi-Fi activo.")).toBeInTheDocument();
    expect(screen.queryByRole("meter")).not.toBeInTheDocument();
    unmount();
    api.supportWifi.mockResolvedValue({ available: true, connected: false });
    render(<WifiView active />);
    expect(await screen.findByText("El Wi-Fi no está conectado a ninguna red.")).toBeInTheDocument();
  });

  it("el historial se pide solo a pedido", async () => {
    const { container } = render(<WifiView active />);
    await screen.findByText("MiRed");
    expect(api.supportWifiHistory).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Ver el historial" }));
    expect(await screen.findByText(/2 eventos recientes · 1 desconexiones/)).toBeInTheDocument();
    expect(container.querySelectorAll("tbody tr")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Volver a leer" })).toBeInTheDocument();
  });

  it("historial no disponible muestra la razón", async () => {
    api.supportWifiHistory.mockResolvedValue({ available: false, reason: "Solo se lee en Windows." });
    render(<WifiView active />);
    await screen.findByText("MiRed");
    await userEvent.click(screen.getByRole("button", { name: "Ver el historial" }));
    expect(await screen.findByText("Solo se lee en Windows.")).toBeInTheDocument();
  });

  it("SSID y mensajes hostiles se ven como texto", async () => {
    const evil = "<script>window.__w=1</script>";
    api.supportWifi.mockResolvedValue(wifi({ ssid: evil }));
    api.supportWifiHistory.mockResolvedValue(hist([{ time: "x", kind: "conectado", message: evil }]));
    const { container } = render(<WifiView active />);
    await screen.findByText(evil);
    await userEvent.click(screen.getByRole("button", { name: "Ver el historial" }));
    await screen.findAllByText(evil);
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText("—")).toBeInTheDocument(); // fecha inválida
  });
});
