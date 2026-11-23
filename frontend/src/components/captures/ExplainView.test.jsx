import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { explain: vi.fn() } }));
import { api } from "../../api/client.js";
import ExplainView, { Ladder } from "./ExplainView.jsx";

const session = { id: 3, protocol: "TCP", src_ip: "10.0.0.1", dst_ip: "93.184.216.34" };
const step = (who, label, detail, ts = 1700000000, packet = 0) => ({ who, label, detail, ts, packet });
const data = (over = {}) => ({
  protocol: "TCP", outcome: "cerrada", summary: ["Frase uno.", "Frase dos."],
  steps: [step("origen", "SYN", "Pide abrir"), step("destino", "SYN+ACK", "Acepta"), step("origen", "ACK", "Confirma")], ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.explain.mockResolvedValue(data());
});
const show = (props = {}) => render(<ExplainView session={session} onError={onError} {...props} />);

describe("Ladder", () => {
  const draw = (steps) => render(<Ladder steps={steps} origin="1.1.1.1" destination="2.2.2.2" />);

  it("cabecera con origen y destino", () => {
    const { container } = draw([step("origen", "SYN", "d")]);
    const spans = container.querySelectorAll(".ladder-head span");
    expect([spans[0].textContent, spans[1].textContent]).toEqual(["Origen · 1.1.1.1", "Destino · 2.2.2.2"]);
  });

  it("una fila por paso con clase y flecha según el sentido", () => {
    const { container } = draw([step("origen", "SYN", "a"), step("destino", "SYN+ACK", "b"), step("ambos", "…", "y 3 paso(s) más", null)]);
    const lis = Array.from(container.querySelectorAll("ol > li"));
    expect(lis.map((l) => l.className)).toEqual(["step step-origen", "step step-destino", "step step-ambos"]);
    expect(lis.map((l) => l.querySelector(".step-arrow").textContent)).toEqual(["───▶", "◀───", "· · ·"]);
    expect(lis.every((l) => l.querySelector(".step-arrow").getAttribute("aria-hidden") === "true")).toBe(true);
  });

  it("aria-label con el sentido hablado, la etiqueta y el detalle", () => {
    const { container } = draw([step("origen", "SYN", "Pide abrir"), step("destino", "RST", "Corta"), step("ambos", "…", "más", null)]);
    const labels = Array.from(container.querySelectorAll("li")).map((l) => l.getAttribute("aria-label"));
    expect(labels).toEqual(["Origen → Destino: SYN. Pide abrir", "Destino → Origen: RST. Corta", "…. más"]);
  });

  it("muestra la hora solo si el paso la trae", () => {
    const { container } = draw([step("origen", "SYN", "a", 1700000000), step("ambos", "…", "b", null)]);
    const details = container.querySelectorAll(".step-detail");
    expect(details[0].textContent).toContain("22:13:20.000 UTC");
    expect(details[1].textContent).toBe("b");
  });

  it("un 'who' desconocido se trata como 'ambos'", () => {
    const { container } = draw([step("otro", "X", "d")]);
    expect(container.querySelector("li").className).toBe("step step-ambos");
  });

  it("texto hostil se muestra como texto", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const { container } = draw([step("origen", evil, evil)]);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector(".step-label").textContent).toBe(evil);
  });

  it("sin pasos: lista vacía sin romper", () => {
    const { container } = draw([]);
    expect(container.querySelectorAll("li")).toHaveLength(0);
  });
});

describe("ExplainView", () => {
  it("muestra 'Analizando la sesión…' y luego las frases y el diagrama", async () => {
    let resolve;
    api.explain.mockReturnValue(new Promise((r) => (resolve = r)));
    const { container } = show();
    expect(screen.getByText("Analizando la sesión…")).toBeInTheDocument();
    resolve(data());
    expect(await screen.findByText("Frase uno.")).toBeInTheDocument();
    expect(screen.queryByText("Analizando la sesión…")).toBeNull();
    expect(screen.getByText("Frase dos.")).toBeInTheDocument();
    expect(container.querySelectorAll(".ladder li")).toHaveLength(3);
    expect(container.querySelector(".ladder-head")).toHaveTextContent("Origen · 10.0.0.1");
    expect(container.querySelector(".ladder-head")).toHaveTextContent("Destino · 93.184.216.34");
  });

  it("título 'En palabras simples' con su ayuda (topic explicacion)", async () => {
    show();
    await screen.findByText("Frase uno.");
    expect(screen.getByRole("heading", { name: /^En palabras simples/ })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Ayuda: / }));
    expect(screen.getByRole("note")).toBeInTheDocument();
  });

  it("sin pasos (UDP/ICMP) no dibuja el diagrama", async () => {
    api.explain.mockResolvedValue(data({ protocol: "UDP", outcome: null, steps: [] }));
    const { container } = show();
    await screen.findByText("Frase uno.");
    expect(container.querySelector(".ladder")).toBeNull();
  });

  it("pide por id de sesión con señal de aborto", async () => {
    show();
    await screen.findByText("Frase uno.");
    expect(api.explain).toHaveBeenCalledWith(3, expect.any(AbortSignal));
  });

  it("al cambiar de sesión vuelve a 'Analizando…' y pide la nueva", async () => {
    const { rerender } = show();
    await screen.findByText("Frase uno.");
    api.explain.mockResolvedValue(data({ summary: ["Otra sesión."] }));
    rerender(<ExplainView session={{ ...session, id: 9 }} onError={onError} />);
    expect(await screen.findByText("Otra sesión.")).toBeInTheDocument();
    expect(screen.queryByText("Frase uno.")).toBeNull();
    expect(api.explain).toHaveBeenLastCalledWith(9, expect.any(AbortSignal));
    expect(api.explain.mock.calls[0][1].aborted).toBe(true);
  });

  it("un error llama a onError y deja el estado de carga", async () => {
    api.explain.mockRejectedValue(new Error("no se pudo"));
    show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("no se pudo"));
    expect(screen.getByText("Analizando la sesión…")).toBeInTheDocument();
  });

  it("un AbortError no se reporta y al desmontar se aborta", async () => {
    api.explain.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    const { unmount } = show();
    await waitFor(() => expect(api.explain).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
    const signal = api.explain.mock.calls[0][1];
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it("frases hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.explain.mockResolvedValue(data({ summary: [evil] }));
    const { container } = show();
    await screen.findByText(evil);
    expect(container.querySelector("img")).toBeNull();
  });
});
