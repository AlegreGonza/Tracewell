import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { supportInternet: vi.fn(), supportLatency: vi.fn() } }));
import { api } from "../../api/client.js";
import InternetCheckView from "./InternetCheckView.jsx";
import LatencyView, { latencyVerdict } from "./LatencyView.jsx";

const step = (code, ok, over = {}) => ({ code, title: `Paso ${code}`, ok, detail: `detalle ${code}`, ms: null, ...over });
const okResult = { ok: true, layer: null, summary: "Todo funciona", advice: null, command: null, steps: [step("adapter", true), step("gateway", true), step("internet", true), step("dns", true)] };

beforeEach(() => vi.clearAllMocks());

describe("InternetCheckView", () => {
  it("no hace nada hasta apretar «Comprobar ahora»", () => {
    render(<InternetCheckView />);
    expect(api.supportInternet).not.toHaveBeenCalled();
  });

  it("todo bien: veredicto y cuatro pasos ✔", async () => {
    api.supportInternet.mockResolvedValue(okResult);
    render(<InternetCheckView />);
    await userEvent.click(screen.getByRole("button", { name: "Comprobar ahora" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Todo funciona");
    expect(screen.getAllByLabelText("bien")).toHaveLength(4);
    expect(screen.getAllByText("✔")).toHaveLength(4);
    expect(screen.queryByText(/Tracewell no lo ejecuta/)).not.toBeInTheDocument();
  });

  it("falla en una capa: ✘ y – (omitido), con consejo y el comando solo como texto", async () => {
    api.supportInternet.mockResolvedValue({
      ok: false, layer: "adaptador", summary: "No consiguió IP", advice: "Revisá el cable", command: "ipconfig /release && ipconfig /renew",
      steps: [step("adapter", false), step("gateway", null), step("internet", null), step("dns", null)],
    });
    render(<InternetCheckView />);
    await userEvent.click(screen.getByRole("button", { name: "Comprobar ahora" }));
    expect(await screen.findByText("Revisá el cable")).toBeInTheDocument();
    expect(screen.getByLabelText("falla")).toHaveTextContent("✘");
    expect(screen.getAllByLabelText("omitido")).toHaveLength(3);
    const code = screen.getByText("ipconfig /release && ipconfig /renew");
    expect(code.tagName).toBe("CODE");
    expect(screen.getByText(/Tracewell no lo ejecuta/)).toBeInTheDocument();
    // solo hay un botón de acción (Comprobar): el comando no es ejecutable desde la UI
    expect(screen.getAllByRole("button").map((b) => b.textContent)).toEqual(["?", "Comprobar ahora"]);
    expect(api.supportInternet).toHaveBeenCalledTimes(1);
  });

  it("mientras comprueba, el botón está deshabilitado; un error se muestra", async () => {
    api.supportInternet.mockRejectedValue(new Error("falló"));
    render(<InternetCheckView />);
    await userEvent.click(screen.getByRole("button", { name: "Comprobar ahora" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("falló");
  });

  it("detalles hostiles como texto", async () => {
    const evil = "<script>window.__y=1</script>";
    api.supportInternet.mockResolvedValue({ ...okResult, steps: [step("adapter", true, { detail: evil })] });
    const { container } = render(<InternetCheckView />);
    await userEvent.click(screen.getByRole("button", { name: "Comprobar ahora" }));
    await screen.findByText(evil);
    expect(container.querySelector("script")).toBeNull();
  });
});

describe("latencyVerdict (umbrales 30/80/150)", () => {
  it.each([
    [null, /No se pudo medir/], [0, /Excelente/], [29.9, /Excelente/], [30, /Buena/], [79.9, /Buena/], [80, /Aceptable/], [149.9, /Aceptable/], [150, /Alta/], [900, /Alta/],
  ])("%s ms", (avg, re) => expect(latencyVerdict(avg)).toMatch(re));
});

describe("LatencyView", () => {
  const res = (over = {}) => ({ host: "1.1.1.1", port: 443, samples: 8, failed: 1, times: [10, 12, 30], min: 10, max: 30, avg: 17.3, jitter: 4.5, router: { host: "192.168.1.1", avg: 2, loss_pct: 0 }, ...over });

  it("mide con el host escrito y muestra veredicto, estadísticas y barras", async () => {
    api.supportLatency.mockResolvedValue(res());
    render(<LatencyView />);
    const input = screen.getByRole("textbox");
    await userEvent.clear(input);
    await userEvent.type(input, "8.8.8.8");
    await userEvent.click(screen.getByRole("button", { name: "Medir" }));
    expect(api.supportLatency.mock.calls[0][0]).toEqual({ host: "8.8.8.8", port: 443, samples: 8 });
    expect(await screen.findByText(/Excelente/)).toBeInTheDocument();
    expect(screen.getByText("17.3 ms")).toBeInTheDocument();
    expect(screen.getByText("1 de 8")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /3 mediciones, entre 10 y 30 ms/ })).toBeInTheDocument();
    expect(screen.getByText(/2 ms · 0 % perdido/)).toBeInTheDocument();
  });

  it("Internet lento con router rápido: avisa que el problema está afuera", async () => {
    api.supportLatency.mockResolvedValue(res({ avg: 200, router: { host: "192.168.1.1", avg: 1, loss_pct: 0 } }));
    render(<LatencyView />);
    await userEvent.click(screen.getByRole("button", { name: "Medir" }));
    expect(await screen.findByText(/fuera de tu red local/)).toBeInTheDocument();
  });

  it("sin mediciones ni router", async () => {
    api.supportLatency.mockResolvedValue(res({ times: [], avg: null, min: null, max: null, jitter: null, router: null, failed: 8 }));
    render(<LatencyView />);
    await userEvent.click(screen.getByRole("button", { name: "Medir" }));
    expect(await screen.findByText("No se pudo medir.")).toBeInTheDocument();
    expect(screen.getByText("no se encontró")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("un error de la API se muestra (422 de host inválido)", async () => {
    api.supportLatency.mockRejectedValue(new Error("el nombre o la IP no es válido"));
    render(<LatencyView />);
    await userEvent.click(screen.getByRole("button", { name: "Medir" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("no es válido");
  });
});
