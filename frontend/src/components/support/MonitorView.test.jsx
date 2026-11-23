import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { monitorStatus: vi.fn(), monitorStart: vi.fn(), monitorStop: vi.fn(), monitorClear: vi.fn() } }));
import { api } from "../../api/client.js";
import MonitorView from "./MonitorView.jsx";

const status = (over = {}) => ({
  running: false, interval: 2, started_at: null, total: 0, availability_pct: null, current: "sin datos", gateway: null, wifi: null,
  latency: { last: null, avg: null, max: null }, samples: [], outages: [], outage_count: 0, downtime_seconds: 0, ...over,
});
const running = (over = {}) => status({
  running: true, total: 50, availability_pct: 96, current: "ok", gateway: "192.168.1.1", wifi: { signal: 70, ssid: "MiRed" },
  latency: { last: 12, avg: 15, max: 40 }, samples: [{ t: 1, ms: 12, layer: null }, { t: 2, ms: null, layer: "dns" }], ...over,
});
const outage = (over = {}) => ({ start: 1700000000, layer: "internet", samples: 3, signal: 55, duration: 12, ongoing: false, ...over });

beforeEach(() => {
  vi.clearAllMocks();
  api.monitorStatus.mockResolvedValue(status());
  api.monitorStart.mockResolvedValue(status({ running: true }));
  api.monitorStop.mockResolvedValue(status());
  api.monitorClear.mockResolvedValue(status());
});

describe("MonitorView", () => {
  it("detenido y vacío: invita a empezar; «Borrar registro» deshabilitado", async () => {
    render(<MonitorView active />);
    expect(await screen.findByText(/Apretá «Empezar a monitorear»/)).toBeInTheDocument();
    expect(screen.getByText("detenido")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Borrar registro" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Detener" })).not.toBeInTheDocument();
  });

  it("empezar usa el intervalo elegido y vuelve a leer el estado", async () => {
    render(<MonitorView active />);
    await screen.findByText("detenido");
    await userEvent.selectOptions(screen.getByRole("combobox"), "5");
    const before = api.monitorStatus.mock.calls.length;
    await userEvent.click(screen.getByRole("button", { name: "Empezar a monitorear" }));
    await waitFor(() => expect(api.monitorStart).toHaveBeenCalledWith(5));
    await waitFor(() => expect(api.monitorStatus.mock.calls.length).toBeGreaterThan(before));
  });

  it("corriendo: «Detener» llama a monitorStop; «Borrar registro» a monitorClear", async () => {
    api.monitorStatus.mockResolvedValue(running());
    render(<MonitorView active />);
    expect(await screen.findByText("midiendo…")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Empezar a monitorear" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Detener" }));
    await waitFor(() => expect(api.monitorStop).toHaveBeenCalledTimes(1));
    await userEvent.click(screen.getByRole("button", { name: "Borrar registro" }));
    await waitFor(() => expect(api.monitorClear).toHaveBeenCalledTimes(1));
  });

  it("estado actual ok, estadísticas y señal Wi-Fi", async () => {
    api.monitorStatus.mockResolvedValue(running());
    render(<MonitorView active />);
    expect(await screen.findByText("Ahora: todo funciona")).toBeInTheDocument();
    expect(screen.getByText("96 % de 50 mediciones")).toBeInTheDocument();
    expect(screen.getByText(/12 ms \(promedio 15, máximo 40\)/)).toBeInTheDocument();
    expect(screen.getByText("70 % (MiRed)")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
    expect(screen.getByText("Sin cortes por ahora.")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Últimas 2 mediciones" })).toBeInTheDocument();
  });

  it("estado actual con falla muestra la capa", async () => {
    api.monitorStatus.mockResolvedValue(running({ current: "dns" }));
    render(<MonitorView active />);
    expect(await screen.findByText("Ahora: falla (dns)")).toBeInTheDocument();
  });

  it("tabla de cortes: más nuevo primero, duración, en curso y qué falló", async () => {
    api.monitorStatus.mockResolvedValue(running({
      outages: [outage({ start: 1700000100, layer: "red local", ongoing: true, duration: 5, signal: null }), outage({ layer: "dns", duration: 61 })],
      outage_count: 2, downtime_seconds: 66,
    }));
    const { container } = render(<MonitorView active />);
    await screen.findByText("Cronología de cortes");
    const rows = Array.from(container.querySelectorAll("tbody tr"));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("(en curso)");
    expect(rows[0]).toHaveTextContent("No llegaba al router");
    expect(rows[1]).toHaveTextContent("Había Internet pero fallaba el DNS");
    expect(rows[1]).toHaveTextContent("55 %");
    expect(screen.getByText(/2 \(1m 6s en total\)|^2 \(/)).toBeInTheDocument();
  });

  it("un error de la API se avisa", async () => {
    api.monitorStatus.mockRejectedValue(new Error("sin conexión con Tracewell"));
    render(<MonitorView active />);
    expect(await screen.findByRole("alert")).toHaveTextContent("sin conexión con Tracewell");
  });

  it("un error al empezar se avisa", async () => {
    api.monitorStart.mockRejectedValue(new Error("no se pudo"));
    render(<MonitorView active />);
    await screen.findByText("detenido");
    await userEvent.click(screen.getByRole("button", { name: "Empezar a monitorear" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("no se pudo");
  });

  it("textos hostiles (SSID) como texto", async () => {
    const evil = "<script>window.__m=1</script>";
    api.monitorStatus.mockResolvedValue(running({ wifi: { signal: 50, ssid: evil } }));
    const { container } = render(<MonitorView active />);
    await screen.findByText(new RegExp("50 % \\("));
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(evil);
  });
});
