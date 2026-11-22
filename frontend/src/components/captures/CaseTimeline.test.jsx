import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { caseTimeline: vi.fn() } }));
import { api } from "../../api/client.js";
import CaseTimeline from "./CaseTimeline.jsx";

const ev = (kind, ts, title, over = {}) => ({ ts, kind, title, detail: "detalle", ips: ["10.0.0.5"], ...over });
const data = (items, over = {}) => ({ host: null, total: items.length, truncated: false, items, ...over });

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.caseTimeline.mockResolvedValue(data([
    ev("dns", 1700000000, "DNS sospechoso: x.evil.test"),
    ev("alerta", 1700000060, "Escaneo de puertos", { severity: "high" }),
    ev("ioc", 1700000120, "Coincide con un IOC: ip:1.2.3.4", { session_id: 3 }),
  ]));
});

describe("CaseTimeline", () => {
  it("lista los hechos en el orden que manda la API, con su tipo en texto", async () => {
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    const list = await screen.findByRole("list", { name: /orden cronológico/ });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("DNS");
    expect(rows[1]).toHaveTextContent("Alerta");
    expect(rows[1]).toHaveTextContent("Alta");
    expect(rows[2]).toHaveTextContent("IOC");
    expect(api.caseTimeline).toHaveBeenCalledWith(undefined, expect.any(AbortSignal));
  });

  it("muestra el total", async () => {
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    expect(await screen.findByText(/3 hechos/)).toBeInTheDocument();
  });

  it("filtrar por equipo vuelve a pedir con esa IP y se puede quitar", async () => {
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    await screen.findByRole("list");
    await userEvent.type(screen.getByLabelText("Equipo (IP)"), " 10.0.0.5 ");
    await userEvent.click(screen.getByRole("button", { name: "Limitar al equipo" }));
    expect(api.caseTimeline).toHaveBeenLastCalledWith("10.0.0.5", expect.any(AbortSignal));
    await userEvent.click(await screen.findByRole("button", { name: "Quitar filtro" }));
    expect(api.caseTimeline).toHaveBeenLastCalledWith(undefined, expect.any(AbortSignal));
  });

  it("sin hechos lo dice", async () => {
    api.caseTimeline.mockResolvedValue(data([]));
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    expect(await screen.findByText("No hay hechos para mostrar.")).toBeInTheDocument();
  });

  it("avisa cuando hay más hechos que los mostrados", async () => {
    api.caseTimeline.mockResolvedValue(data([ev("alerta", 1, "A", { severity: "low" })], { total: 900, truncated: true }));
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    expect(await screen.findByRole("note")).toHaveTextContent("Hay más hechos");
  });

  it("el botón de cada hecho filtra las sesiones por su IP", async () => {
    const onFilterIp = vi.fn();
    render(<CaseTimeline refreshKey={0} onError={onError} onFilterIp={onFilterIp} />);
    const [first] = await screen.findAllByRole("button", { name: /Ver sesiones de 10.0.0.5/ });
    await userEvent.click(first);
    expect(onFilterIp).toHaveBeenCalledWith("10.0.0.5");
  });

  it("un error de la API se informa", async () => {
    api.caseTimeline.mockRejectedValue(new Error("422"));
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("422"));
  });

  it("recarga cuando cambia el triaje (nota nueva o IOC)", async () => {
    const { rerender } = render(<CaseTimeline refreshKey={0} triageVersion={0} onError={onError} />);
    await screen.findByRole("list");
    rerender(<CaseTimeline refreshKey={0} triageVersion={1} onError={onError} />);
    await vi.waitFor(() => expect(api.caseTimeline).toHaveBeenCalledTimes(2));
  });

  it("los textos de la captura no se interpretan como HTML", async () => {
    api.caseTimeline.mockResolvedValue(data([ev("dns", 1, "<img src=x onerror=alert(1)>", { detail: "<b>x</b>" })]));
    render(<CaseTimeline refreshKey={0} onError={onError} />);
    await screen.findByRole("list");
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("b")).toBeNull();
  });
});
