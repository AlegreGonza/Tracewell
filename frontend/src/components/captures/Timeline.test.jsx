import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const chart = vi.hoisted(() => ({ props: null }));
vi.mock("@mantine/charts", () => ({
  BarChart: (props) => {
    chart.props = props;
    return <div data-testid="bar-chart" />;
  },
}));
vi.mock("../../api/client.js", () => ({ api: { timeline: vi.fn() } }));
import { api } from "../../api/client.js";
import Timeline from "./Timeline.jsx";

const data = (over = {}) => ({
  start: 1700000000, bucket_seconds: 2, packets: [1, 5, 3], bytes: [100, 50, 9000], ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  chart.props = null;
  onError = vi.fn();
  api.timeline.mockResolvedValue(data());
});

const show = (props = {}) => render(<Timeline refreshKey={0} onError={onError} {...props} />);
const values = () => chart.props.data.map((d) => d.value);
const colors = () => values().map((v) => chart.props.getBarColor(v));
const peaks = () => colors().map((c) => c === "orange.5");

describe("Timeline", () => {
  it("no dibuja nada mientras carga", () => {
    api.timeline.mockReturnValue(new Promise(() => {}));
    const { container } = show();
    expect(container).toBeEmptyDOMElement();
  });

  it.each([
    ["packets vacío", { packets: [], bytes: [] }],
    ["packets ausente", { packets: undefined }],
    ["packets null", { packets: null }],
  ])("no dibuja nada con %s", async (_n, over) => {
    api.timeline.mockResolvedValue(data(over));
    const { container } = show();
    await waitFor(() => expect(api.timeline).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("no dibuja nada si la respuesta es null", async () => {
    api.timeline.mockResolvedValue(null);
    const { container } = show();
    await waitFor(() => expect(api.timeline).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("una barra por intervalo con hora y valor; solo el pico va en naranja", async () => {
    show();
    await screen.findByRole("img");
    expect(chart.props.data).toEqual([
      { time: "22:13:20", value: 1 }, { time: "22:13:22", value: 5 }, { time: "22:13:24", value: 3 },
    ]);
    expect(chart.props.dataKey).toBe("time");
    expect(colors()).toEqual(["tw.5", "orange.5", "tw.5"]);
  });

  it("los valores guardan la proporción de los datos y la serie es Paquetes", async () => {
    show();
    await screen.findByRole("img");
    expect(values()).toEqual([1, 5, 3]);
    expect(chart.props.series).toEqual([{ name: "value", label: "Paquetes", color: "tw.5" }]);
    expect(chart.props.valueFormatter(1234)).toBe(`${(1234).toLocaleString("es-AR")} paquetes`);
  });

  it("role=img con un aria-label que resume intervalos, pico y hora", async () => {
    show();
    const svg = await screen.findByRole("img");
    const label = svg.getAttribute("aria-label");
    expect(label).toContain("3 intervalos");
    expect(label).toContain("2.00 s");
    expect(label).toContain("Pico de 5 paquetes");
    expect(label).toContain("22:13:22.000 UTC"); // 1700000000 + 1 * 2 s
  });

  it("la leyenda en texto repite el resumen y muestra el eje", async () => {
    show();
    const svg = await screen.findByRole("img");
    expect(screen.getByText(svg.getAttribute("aria-label"))).toBeInTheDocument();
    expect(screen.getByText("22:13:20.000 UTC")).toBeInTheDocument(); // primera barra
    expect(screen.getByText("22:13:24.000 UTC")).toBeInTheDocument(); // ultima barra
    expect(screen.getByText("cada barra = 2.00 s")).toBeInTheDocument();
  });

  it("el selector cambia entre Paquetes y Bytes (valores, pico, serie y formato)", async () => {
    show();
    await screen.findByRole("img");
    const sel = screen.getByRole("combobox", { name: /Mostrar/ });
    expect(sel).toHaveValue("packets");
    expect(screen.getByRole("option", { name: "Paquetes" })).toBeInTheDocument();
    await userEvent.selectOptions(sel, "bytes");
    expect(sel).toHaveValue("bytes");
    expect(values()).toEqual([100, 50, 9000]);
    expect(peaks()).toEqual([false, false, true]);
    expect(chart.props.series[0].label).toBe("Bytes");
    expect(chart.props.valueFormatter(9000)).toBe(`${(9000).toLocaleString("es-AR")} bytes`);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("Pico de 9.000 bytes");
    await userEvent.selectOptions(sel, "packets");
    expect(values()).toEqual([1, 5, 3]);
    expect(peaks()).toEqual([false, true, false]);
    expect(chart.props.series[0].label).toBe("Paquetes");
    expect(api.timeline).toHaveBeenCalledTimes(1); // cambiar de métrica no vuelve a pedir
  });

  it("sin `bytes` en la respuesta, la métrica Bytes cae a paquetes y no rompe", async () => {
    api.timeline.mockResolvedValue(data({ bytes: undefined }));
    show();
    await screen.findByRole("img");
    await userEvent.selectOptions(screen.getByRole("combobox"), "bytes");
    expect(chart.props.data).toHaveLength(3);
  });

  it("todo en cero: sin NaN y pico en la primera barra", async () => {
    api.timeline.mockResolvedValue(data({ packets: [0, 0, 0], bytes: [0, 0, 0] }));
    show();
    const img = await screen.findByRole("img");
    expect(values()).toEqual([0, 0, 0]);
    expect(peaks()).toEqual([true, true, true]); // getBarColor compara por valor: todos coinciden con el pico (0)
    expect(JSON.stringify(chart.props.data)).not.toMatch(/NaN/);
    expect(img.getAttribute("aria-label")).not.toMatch(/NaN/);
    expect(img.getAttribute("aria-label")).toContain("Pico de 0 paquetes a las 22:13:20.000 UTC");
  });

  it("empate en el máximo: el texto cita la primera barra; el color marca por valor", async () => {
    api.timeline.mockResolvedValue(data({ packets: [4, 9, 9, 2] }));
    show();
    const img = await screen.findByRole("img");
    expect(img.getAttribute("aria-label")).toContain("a las 22:13:22.000 UTC"); // primer máximo
    expect(peaks()).toEqual([false, true, true, false]); // reflejo del código: v === valor del pico
  });

  it("una sola barra", async () => {
    api.timeline.mockResolvedValue(data({ packets: [7], bytes: [70] }));
    show();
    await screen.findByRole("img");
    expect(chart.props.data).toHaveLength(1);
    expect(peaks()).toEqual([true]);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("1 intervalos");
  });

  it("120 barras (el máximo)", async () => {
    api.timeline.mockResolvedValue(data({ packets: Array.from({ length: 120 }, (_, i) => i), bytes: [] }));
    show();
    await screen.findByRole("img");
    expect(chart.props.data).toHaveLength(120);
    expect(peaks().filter(Boolean)).toHaveLength(1);
    expect(peaks()[119]).toBe(true);
  });

  it("pide los datos con una señal de aborto y vuelve a pedir si cambia refreshKey", async () => {
    const { rerender } = show();
    await screen.findByRole("img");
    expect(api.timeline).toHaveBeenCalledTimes(1);
    expect(api.timeline.mock.calls[0][0]).toBeInstanceOf(AbortSignal);
    api.timeline.mockResolvedValue(data({ packets: [9, 9] }));
    rerender(<Timeline refreshKey={1} onError={onError} />);
    await waitFor(() => expect(chart.props?.data).toHaveLength(2));
    expect(api.timeline).toHaveBeenCalledTimes(2);
    expect(api.timeline.mock.calls[0][0].aborted).toBe(true); // el pedido viejo se cancela
    rerender(<Timeline refreshKey={1} onError={onError} />);
    expect(api.timeline).toHaveBeenCalledTimes(2); // mismo refreshKey: no repite
  });

  it("un pedido viejo que se resuelve tarde no provoca errores", async () => {
    let resolveOld;
    api.timeline.mockReturnValueOnce(new Promise((r) => (resolveOld = r)));
    const { rerender } = show();
    api.timeline.mockResolvedValue(data({ packets: [1, 1] }));
    rerender(<Timeline refreshKey={1} onError={onError} />);
    await waitFor(() => expect(chart.props?.data).toHaveLength(2));
    resolveOld(data({ packets: [1, 2, 3, 4] })); // el fetch real lo rechazaría con AbortError; aquí solo no debe romper
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
  });

  it("un error del servidor llama a onError con el mensaje y no dibuja", async () => {
    api.timeline.mockRejectedValue(new Error("boom"));
    const { container } = show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("boom"));
    expect(container).toBeEmptyDOMElement();
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("un AbortError no se reporta", async () => {
    api.timeline.mockRejectedValue(Object.assign(new Error("abort"), { name: "AbortError" }));
    show();
    await waitFor(() => expect(api.timeline).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
  });

  it("al desmontar aborta el pedido en curso", async () => {
    api.timeline.mockReturnValue(new Promise(() => {}));
    const { unmount } = show();
    const signal = api.timeline.mock.calls[0][0];
    expect(signal.aborted).toBe(false);
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it("start no numérico muestra '—' en las horas sin romper", async () => {
    api.timeline.mockResolvedValue(data({ start: "x" }));
    const { container } = show();
    await screen.findByRole("img");
    expect(container.querySelector(".timeline-axis").textContent).toContain("—");
  });

  it.each([
    ["vacío", []],
    ["más corto", [1]],
    ["más largo", [1, 2, 3, 4]],
    ["ausente", undefined],
    ["null", null],
    ["no es arreglo", "abc"],
  ])("con `bytes` %s, la métrica Bytes muestra las barras de paquetes sin romper", async (_n, bytes) => {
    api.timeline.mockResolvedValue(data({ bytes }));
    show();
    await screen.findByRole("img");
    await userEvent.selectOptions(screen.getByRole("combobox"), "bytes");
    expect(values()).toEqual([1, 5, 3]);
    expect(peaks()).toEqual([false, true, false]);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("Pico de 5");
  });
});
