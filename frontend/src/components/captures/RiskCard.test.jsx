import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({ api: { alerts: vi.fn() } }));
import { api } from "../../api/client.js";
import RiskCard, { riskScore, riskLevel, RISK_WEIGHT } from "./RiskCard.jsx";

const al = (severity, name = `Regla ${severity}`, i = 0) => ({ rule_id: `r${i}`, name, severity });
const abort = () => Object.assign(new Error("x"), { name: "AbortError" });
let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.alerts.mockResolvedValue([]);
});
const why = () => within(screen.getByRole("list", { name: "Por qué este puntaje" })).getAllByRole("listitem");

describe("riskScore / riskLevel / RISK_WEIGHT", () => {
  it("pesos por severidad", () => {
    expect(RISK_WEIGHT).toEqual({ critical: 35, high: 25, medium: 12, low: 5 });
  });
  it("suma los pesos y respeta el tope de 100", () => {
    expect(riskScore([])).toBe(0);
    expect(riskScore([al("critical"), al("high")])).toBe(60);
    expect(riskScore([al("medium"), al("low")])).toBe(17);
    expect(riskScore([al("critical"), al("critical"), al("critical")])).toBe(100);
    expect(riskScore(Array.from({ length: 50 }, () => al("low")))).toBe(100);
  });
  it("una severidad desconocida pesa 5", () => {
    expect(riskScore([al("rara")])).toBe(5);
  });
  it("niveles: 0 sin alertas, 1-39 bajo, 40-69 medio, 70+ alto", () => {
    expect(riskLevel(0)).toMatchObject({ id: "nulo", text: "Sin alertas" });
    expect(riskLevel(1).id).toBe("bajo");
    expect(riskLevel(39).id).toBe("bajo");
    expect(riskLevel(40).id).toBe("medio");
    expect(riskLevel(69).id).toBe("medio");
    expect(riskLevel(70).id).toBe("alto");
    expect(riskLevel(100).text).toBe("Alto");
  });
});

describe("RiskCard", () => {
  it("pide las alertas sin filtros y con signal; no dibuja nada hasta que llegan", () => {
    api.alerts.mockReturnValue(new Promise(() => {}));
    const { container } = render(<RiskCard refreshKey={0} onError={onError} />);
    expect(container).toBeEmptyDOMElement();
    expect(api.alerts).toHaveBeenCalledWith(undefined, expect.any(AbortSignal));
  });

  it("muestra el puntaje, el nivel y el motivo de cada alerta con su forma", async () => {
    api.alerts.mockResolvedValue([al("critical", "Crítica X"), al("high", "Alta X"), al("medium", "Media X"), al("low", "Baja X")]);
    render(<RiskCard refreshKey={0} onError={onError} />);
    expect(await screen.findByRole("heading", { name: /Puntaje de riesgo/ })).toBeInTheDocument();
    expect(screen.getByText("77")).toBeInTheDocument();
    expect(screen.getByText("Alto")).toBeInTheDocument();
    expect(why().map((li) => li.textContent)).toEqual([
      "◆Crítica X+35 · crítica", "▲Alta X+25 · alta", "●Media X+12 · media", "▼Baja X+5 · baja",
    ]);
  });

  it("ordena por gravedad y muestra solo los 5 principales", async () => {
    api.alerts.mockResolvedValue([
      al("low", "L1", 1), al("medium", "M1", 2), al("high", "H1", 3), al("low", "L2", 4), al("critical", "C1", 5), al("medium", "M2", 6), al("low", "L3", 7),
    ]);
    render(<RiskCard refreshKey={0} onError={onError} />);
    await screen.findByText("C1");
    const items = why();
    expect(items).toHaveLength(5);
    expect(items[0]).toHaveTextContent("C1");
    expect(items[1]).toHaveTextContent("H1");
    expect(screen.getByText("99")).toBeInTheDocument(); // el puntaje cuenta todas las alertas, no solo las 5 visibles
  });

  it("sin alertas: «Sin alertas» y puntaje 0", async () => {
    render(<RiskCard refreshKey={0} onError={onError} />);
    expect((await screen.findAllByText("Sin alertas")).length).toBeGreaterThan(0);
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText(/no hay nada que sumar/)).toBeInTheDocument();
  });

  it("acepta también una respuesta {items: [...]}", async () => {
    api.alerts.mockResolvedValue({ items: [al("high", "Con items")] });
    render(<RiskCard refreshKey={0} onError={onError} />);
    expect(await screen.findByText("Con items")).toBeInTheDocument();
    expect(screen.getByText("25")).toBeInTheDocument();
  });

  it("un error se informa por onError", async () => {
    api.alerts.mockRejectedValue(new Error("falló"));
    render(<RiskCard refreshKey={0} onError={onError} />);
    await waitFor(() => expect(onError).toHaveBeenCalledWith("falló"));
  });

  it("un AbortError no se informa", async () => {
    api.alerts.mockRejectedValue(abort());
    render(<RiskCard refreshKey={0} onError={onError} />);
    await new Promise((r) => setTimeout(r, 10));
    expect(onError).not.toHaveBeenCalled();
  });

  it("el nombre de una alerta con <script> se ve como texto", async () => {
    const evil = "<script>alert(1)</script>";
    api.alerts.mockResolvedValue([al("high", evil)]);
    const { container } = render(<RiskCard refreshKey={0} onError={onError} />);
    expect(await screen.findByText(evil)).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});
