import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({
  api: { interfaces: vi.fn(), liveStart: vi.fn(), liveStatus: vi.fn(), liveStop: vi.fn() },
}));
import { api } from "../../api/client.js";
import LivePanel from "./LivePanel.jsx";

const st = (over = {}) => ({ state: "running", packets: 5, bytes: 500, seconds: 1, reason: null, ...over });
const flush = () => act(async () => {});
const tick = (ms = 1000) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const click = async (name) => {
  fireEvent.click(screen.getByRole("button", { name }));
  await flush();
};

let onAnalyzed, onError;
beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  onAnalyzed = vi.fn();
  onError = vi.fn();
  api.interfaces.mockResolvedValue([
    { name: "eth0", description: "eth0" },
    { name: "\\Device\\NPF_{1}", description: "Wi-Fi" },
  ]);
  api.liveStart.mockResolvedValue(st());
});
afterEach(() => vi.useRealTimers());

const open = async () => {
  render(<LivePanel onAnalyzed={onAnalyzed} onError={onError} disabled={false} />);
  await click("Mostrar");
};

describe("LivePanel", () => {
  it("está cerrado al inicio y no pide interfaces", () => {
    render(<LivePanel onAnalyzed={onAnalyzed} onError={onError} />);
    expect(screen.getByRole("button", { name: "Mostrar" })).toHaveAttribute("aria-expanded", "false");
    expect(api.interfaces).not.toHaveBeenCalled();
  });

  it("Mostrar carga las interfaces (una sola vez) y las lista", async () => {
    await open();
    expect(screen.getByRole("combobox", { name: "Interfaz" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "eth0" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "\\Device\\NPF_{1} — Wi-Fi" })).toBeInTheDocument();
    await click("Ocultar");
    await click("Mostrar");
    expect(api.interfaces).toHaveBeenCalledTimes(1);
  });

  it("preselecciona la primera interfaz de la lista", async () => {
    api.interfaces.mockResolvedValue([
      { name: "Wi-Fi", description: "Wi-Fi" },
      { name: "eth0", description: "eth0" },
      { name: "lo", description: "lo" },
    ]);
    await open();
    expect(screen.getByRole("combobox", { name: "Interfaz" })).toHaveValue("Wi-Fi");
    await click("Iniciar captura");
    expect(api.liveStart).toHaveBeenCalledWith({ interface: "Wi-Fi" });
  });

  it("sin interfaces avisa", async () => {
    api.interfaces.mockResolvedValue([]);
    await open();
    expect(screen.getByText("No se encontraron interfaces.")).toBeInTheDocument();
  });

  it("error al cargar interfaces -> onError", async () => {
    api.interfaces.mockRejectedValue(new Error("sin Npcap"));
    await open();
    expect(onError).toHaveBeenCalledWith("sin Npcap");
  });

  it("iniciar envía la interfaz elegida y muestra el estado", async () => {
    await open();
    fireEvent.change(screen.getByRole("combobox", { name: "Interfaz" }), { target: { value: "\\Device\\NPF_{1}" } });
    await click("Iniciar captura");
    expect(api.liveStart).toHaveBeenCalledWith({ interface: "\\Device\\NPF_{1}" });
    expect(screen.getByRole("status")).toHaveTextContent("Capturando…");
    expect(screen.getByRole("button", { name: "Detener y analizar" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Interfaz" })).toBeDisabled();
  });

  it("Iniciar deshabilitado si disabled=true", async () => {
    render(<LivePanel onAnalyzed={onAnalyzed} onError={onError} disabled />);
    await click("Mostrar");
    expect(screen.getByRole("button", { name: "Iniciar captura" })).toBeDisabled();
  });

  it("error al iniciar -> onError y no queda capturando", async () => {
    api.liveStart.mockRejectedValue(new Error("ejecutá como administrador"));
    await open();
    await click("Iniciar captura");
    expect(onError).toHaveBeenCalledWith("ejecutá como administrador");
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByRole("button", { name: "Iniciar captura" })).toBeInTheDocument();
  });

  it("detener manualmente pide stop y entrega el análisis", async () => {
    api.liveStop.mockResolvedValue({ capture: { reason: "manual" }, analysis: { id: "A" } });
    await open();
    await click("Iniciar captura");
    await click("Detener y analizar");
    expect(api.liveStop).toHaveBeenCalledTimes(1);
    expect(onAnalyzed).toHaveBeenCalledWith({ id: "A" });
    expect(screen.getByRole("status")).toHaveTextContent("Captura terminada.");
    expect(screen.getByRole("status")).toHaveTextContent("(detenida manualmente)");
  });

  it("el sondeo actualiza el contador mientras corre", async () => {
    api.liveStatus.mockResolvedValue(st({ packets: 1234, bytes: 2048, seconds: 3.26 }));
    await open();
    await click("Iniciar captura");
    await tick(1000);
    expect(api.liveStatus).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status")).toHaveTextContent("1.234");
    expect(screen.getByRole("status")).toHaveTextContent("2.00 KB");
    expect(screen.getByRole("status")).toHaveTextContent("3.3 s");
    expect(api.liveStop).not.toHaveBeenCalled();
  });

  it("al detectar state=finished pide stop/análisis UNA sola vez, con la razón en español", async () => {
    api.liveStatus
      .mockResolvedValueOnce(st())
      .mockResolvedValue(st({ state: "finished", reason: "max_packets" }));
    api.liveStop.mockResolvedValue({ capture: { reason: "max_packets" }, analysis: { id: "B" } });
    await open();
    await click("Iniciar captura");
    await tick(1000);
    expect(api.liveStop).not.toHaveBeenCalled();
    await tick(1000);
    expect(api.liveStop).toHaveBeenCalledTimes(1);
    expect(onAnalyzed).toHaveBeenCalledTimes(1);
    expect(onAnalyzed).toHaveBeenCalledWith({ id: "B" });
    await tick(10000);
    expect(api.liveStop).toHaveBeenCalledTimes(1);
    expect(onAnalyzed).toHaveBeenCalledTimes(1);
    expect(api.liveStatus).toHaveBeenCalledTimes(2); // el sondeo se detuvo
    expect(screen.getByRole("status")).toHaveTextContent("(alcanzó el máximo de paquetes)");
  });

  it.each([
    ["max_seconds", "alcanzó el tiempo máximo"],
    ["max_bytes", "alcanzó el tamaño máximo"],
    ["error", "se detuvo por un error de escritura"],
    ["otra_cosa", "otra_cosa"],
  ])("razón %s -> %s", async (reason, text) => {
    api.liveStatus.mockResolvedValue(st({ state: "finished", reason }));
    api.liveStop.mockResolvedValue({ capture: { reason }, analysis: {} });
    await open();
    await click("Iniciar captura");
    await tick(1000);
    expect(screen.getByRole("status")).toHaveTextContent(`(${text})`);
  });

  it("error del sondeo -> onError y sigue sondeando", async () => {
    api.liveStatus.mockRejectedValueOnce(new Error("se cayó")).mockResolvedValue(st());
    await open();
    await click("Iniciar captura");
    await tick(1000);
    expect(onError).toHaveBeenCalledWith("se cayó");
    await tick(1000);
    expect(api.liveStatus).toHaveBeenCalledTimes(2);
  });

  it("error en stop automático -> onError y no se entrega análisis", async () => {
    api.liveStatus.mockResolvedValue(st({ state: "finished", reason: "max_bytes" }));
    api.liveStop.mockRejectedValue(new Error("falló el análisis"));
    await open();
    await click("Iniciar captura");
    await tick(1000);
    expect(onError).toHaveBeenCalledWith("falló el análisis");
    expect(onAnalyzed).not.toHaveBeenCalled();
  });

  it("desmontar limpia el intervalo", async () => {
    api.liveStatus.mockResolvedValue(st());
    const { unmount } = render(<LivePanel onAnalyzed={onAnalyzed} onError={onError} />);
    await click("Mostrar");
    await click("Iniciar captura");
    expect(vi.getTimerCount()).toBeGreaterThan(0);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  describe("aviso (warning) al detener", () => {
    const WARN = "la fuente no se detuvo en 10 s; se cerró el archivo igual";

    it("warning del stop -> aviso role=note, análisis entregado y razón en español", async () => {
      api.liveStop.mockResolvedValue({ capture: { reason: "manual", warning: WARN }, analysis: { id: "W" } });
      await open();
      await click("Iniciar captura");
      await click("Detener y analizar");
      expect(screen.getByRole("note")).toHaveTextContent(`Atención: ${WARN}`);
      expect(onAnalyzed).toHaveBeenCalledWith({ id: "W" });
      expect(screen.getByRole("status")).toHaveTextContent("(detenida manualmente)");
    });

    it.each([["null", { reason: "manual", warning: null }], ["ausente", { reason: "manual" }]])(
      "warning %s -> sin aviso",
      async (_n, capture) => {
        api.liveStop.mockResolvedValue({ capture, analysis: {} });
        await open();
        await click("Iniciar captura");
        await click("Detener y analizar");
        expect(screen.getByRole("status")).toHaveTextContent("Captura terminada.");
        expect(screen.queryByRole("note")).toBeNull();
        expect(screen.queryByText(/Atención/)).toBeNull();
      },
    );

    it("no hay aviso mientras corre, aunque el estado traiga warning", async () => {
      api.liveStart.mockResolvedValue(st({ warning: WARN }));
      api.liveStatus.mockResolvedValue(st({ warning: WARN }));
      await open();
      await click("Iniciar captura");
      expect(screen.queryByRole("note")).toBeNull();
      await tick(1000);
      expect(screen.getByRole("status")).toHaveTextContent("Capturando…");
      expect(screen.queryByRole("note")).toBeNull();
    });

    it("el sondeo con state=finished y warning muestra el aviso tras el stop", async () => {
      api.liveStatus.mockResolvedValue(st({ state: "finished", reason: "max_bytes", warning: WARN }));
      api.liveStop.mockResolvedValue({ capture: { reason: "max_bytes", warning: WARN }, analysis: { id: "P" } });
      await open();
      await click("Iniciar captura");
      await tick(1000);
      expect(screen.getByRole("note")).toHaveTextContent(`Atención: ${WARN}`);
      expect(screen.getByRole("status")).toHaveTextContent("(alcanzó el tamaño máximo)");
    });

    it("HTML hostil se muestra como texto, sin crear elementos", async () => {
      const evil = "<img src=x onerror=alert(1)>";
      api.liveStop.mockResolvedValue({ capture: { reason: "manual", warning: evil }, analysis: {} });
      await open();
      await click("Iniciar captura");
      await click("Detener y analizar");
      const note = screen.getByRole("note");
      expect(note).toHaveTextContent(`Atención: ${evil}`);
      expect(note.querySelector("img")).toBeNull();
      expect(document.querySelector("img")).toBeNull();
    });

    it("una captura nueva limpia el aviso anterior", async () => {
      api.liveStop.mockResolvedValue({ capture: { reason: "manual", warning: WARN }, analysis: {} });
      await open();
      await click("Iniciar captura");
      await click("Detener y analizar");
      expect(screen.getByRole("note")).toBeInTheDocument();
      await click("Iniciar captura");
      expect(screen.getByRole("status")).toHaveTextContent("Capturando…");
      expect(screen.queryByRole("note")).toBeNull();
    });
  });
});
