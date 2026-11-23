import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { systemOverview: vi.fn() } }));
import { api } from "../../api/client.js";
import SystemOverview, { Meter } from "./SystemOverview.jsx";

const data = (over = {}) => ({
  cpu_percent: 12.5, cpu_count: 8, cpu_physical: 4,
  memory: { total: 16 * 1024 ** 3, available: 6 * 1024 ** 3, used: 10 * 1024 ** 3, percent: 62.5 },
  swap: { total: 2 * 1024 ** 3, used: 1024 ** 3, percent: 50 },
  disks: [{ mount: "C:\\", fstype: "NTFS", total: 500 * 1024 ** 3, used: 250 * 1024 ** 3, percent: 50 }],
  network_total: { sent: 2048, received: 4096 }, battery: { percent: 80.5, plugged: true }, uptime_seconds: 7200, process_count: 123, ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  api.systemOverview.mockResolvedValue(data());
});
afterEach(() => vi.useRealTimers());

describe("Meter", () => {
  const meter = () => screen.getByRole("meter");

  it("role=meter con etiqueta, rango y valor actual", () => {
    render(<Meter label="Memoria" percent={62.5} detail="10 GB usados" />);
    expect(meter()).toHaveAccessibleName("Memoria");
    expect(meter()).toHaveAttribute("aria-valuemin", "0");
    expect(meter()).toHaveAttribute("aria-valuemax", "100");
    expect(meter()).toHaveAttribute("aria-valuenow", "62.5");
    expect(screen.getByText("62.5 %")).toBeInTheDocument();
    expect(screen.getByText("10 GB usados")).toBeInTheDocument();
  });

  it("el número siempre está en texto (el color solo refuerza)", () => {
    render(<Meter label="CPU" percent={99.04} />);
    expect(screen.getByText("99.0 %")).toBeInTheDocument();
  });

  it.each([[0, "ok"], [74.9, "ok"], [75, "mid"], [89.9, "mid"], [90, "high"], [100, "high"]])("%s %% -> nivel %s", (p, level) => {
    render(<Meter label="x" percent={p} />);
    expect(meter().className).toBe(`meter meter-${level}`);
  });

  it("valores fuera de rango se acotan a 0..100 en la barra", () => {
    const { rerender } = render(<Meter label="x" percent={150} />);
    expect(meter()).toHaveAttribute("aria-valuenow", "100");
    expect(meter().firstChild).toHaveStyle({ width: "100%" });
    rerender(<Meter label="x" percent={-20} />);
    expect(meter()).toHaveAttribute("aria-valuenow", "0");
    expect(meter().firstChild).toHaveStyle({ width: "0%" });
  });

  it.each([[null], [undefined], [NaN], [Infinity]])("porcentaje %s se muestra como '—' y barra vacía", (p) => {
    render(<Meter label="x" percent={p} />);
    expect(screen.getByText("—")).toBeInTheDocument();
    expect(meter()).toHaveAttribute("aria-valuenow", "0");
  });

  it("sin detalle no dibuja la línea de detalle", () => {
    const { container } = render(<Meter label="x" percent={10} />);
    expect(container.querySelector(".meter-detail")).toBeNull();
  });

  it("la etiqueta hostil es texto", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const { container } = render(<Meter label={evil} percent={1} detail={evil} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getAllByText(evil)).toHaveLength(2);
  });
});

describe("SystemOverview", () => {
  const show = (props = {}) => render(<SystemOverview active {...props} />);

  it("mientras carga: 'Leyendo el equipo…'", () => {
    api.systemOverview.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Leyendo el equipo…")).toBeInTheDocument();
  });

  it("pide los datos al montarse con una señal de aborto", async () => {
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    expect(api.systemOverview).toHaveBeenCalledTimes(1);
    expect(api.systemOverview.mock.calls[0][0]).toBeInstanceOf(AbortSignal);
  });

  it("muestra memoria, procesador, memoria virtual y discos como medidores", async () => {
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    const meters = screen.getAllByRole("meter");
    expect(meters.map((m) => m.getAttribute("aria-label"))).toEqual(["Memoria (RAM)", "Procesador", "Memoria virtual (archivo de paginación)", "Disco C:\\"]);
    expect(screen.getByText("10.0 GB usados de 16.0 GB · 6.00 GB libres")).toBeInTheDocument();
    expect(screen.getByText("8 hilos (4 núcleos físicos)")).toBeInTheDocument();
    expect(screen.getByText("250.0 GB de 500.0 GB · NTFS")).toBeInTheDocument();
  });

  it("datos sueltos: tiempo encendida, procesos, red y batería", async () => {
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    expect(screen.getByText("Encendida hace").nextSibling).toHaveTextContent("2 h 0 min");
    expect(screen.getByText("Procesos en marcha").nextSibling).toHaveTextContent("123");
    expect(screen.getByText("Red desde el arranque").nextSibling).toHaveTextContent("4.00 KB recibidos · 2.00 KB enviados");
    expect(screen.getByText("Batería").nextSibling).toHaveTextContent("80.5 % (enchufada)");
  });

  it("batería con batería y sin enchufar", async () => {
    api.systemOverview.mockResolvedValue(data({ battery: { percent: 20, plugged: false } }));
    show();
    expect(await screen.findByText("20 % (con batería)")).toBeInTheDocument();
  });

  it("datos ausentes: sin swap, sin red, sin batería y sin hora de arranque", async () => {
    api.systemOverview.mockResolvedValue(data({ swap: null, network_total: null, battery: null, uptime_seconds: null, disks: [], cpu_physical: null }));
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    expect(screen.queryByText(/Memoria virtual/)).toBeNull();
    expect(screen.queryByText("Red desde el arranque")).toBeNull();
    expect(screen.queryByText("Batería")).toBeNull();
    expect(screen.getByText("Encendida hace").nextSibling).toHaveTextContent("—");
    expect(screen.getByText(/8 hilos \(\? núcleos físicos\)/)).toBeInTheDocument();
    expect(screen.getAllByRole("meter")).toHaveLength(2);
  });

  it("uptime 0 es un valor válido (no '—')", async () => {
    api.systemOverview.mockResolvedValue(data({ uptime_seconds: 0 }));
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    expect(screen.getByText("Encendida hace").nextSibling).not.toHaveTextContent("—");
  });

  it("un error se muestra como alerta y no hay medidores", async () => {
    api.systemOverview.mockRejectedValue(new Error("Falta la librería psutil"));
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("Falta la librería psutil");
    expect(screen.queryByRole("meter")).toBeNull();
  });

  it("Actualizar vuelve a pedir y se deshabilita mientras carga", async () => {
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    let resolve;
    api.systemOverview.mockReturnValue(new Promise((r) => (resolve = r)));
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    expect(screen.getByRole("button", { name: "Actualizar" })).toBeDisabled();
    await act(async () => resolve(data({ process_count: 999 })));
    expect(await screen.findByText("999")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Actualizar" })).toBeEnabled();
  });

  it("se actualiza sola cada 5 s mientras está activa", async () => {
    vi.useFakeTimers();
    show({ active: true });
    await act(async () => {});
    expect(api.systemOverview).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(api.systemOverview).toHaveBeenCalledTimes(2);
  });

  it("no se actualiza sola si no está activa (la pantalla está oculta)", async () => {
    vi.useFakeTimers();
    show({ active: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(api.systemOverview).toHaveBeenCalledTimes(1);
  });

  it("al desmontar aborta el pedido", () => {
    api.systemOverview.mockReturnValue(new Promise(() => {}));
    const { unmount } = show();
    const signal = api.systemOverview.mock.calls[0][0];
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it("el punto de montaje hostil de un disco es texto", async () => {
    const evil = "<script>alert(1)</script>";
    api.systemOverview.mockResolvedValue(data({ disks: [{ mount: evil, fstype: evil, total: 10, used: 5, percent: 50 }] }));
    const { container } = show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByRole("meter", { name: `Disco ${evil}` })).toBeInTheDocument();
  });

  it("tiene su botón de ayuda y no tiene botones que modifiquen nada", async () => {
    show();
    await screen.findByRole("heading", { name: "Resumen del equipo" });
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/terminar|matar|apagar|reiniciar|borrar|desactivar|liberar/i);
  });
});
