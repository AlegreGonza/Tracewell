import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ErrorBoundary from "./ErrorBoundary.jsx";

const Bomb = ({ msg = "kaboom secreto" }) => {
  throw new Error(msg);
};

const originalLocation = window.location;
const mockReload = () => {
  const reload = vi.fn();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { ...window.location, reload },
  });
  return reload;
};

afterEach(() => {
  Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
  vi.restoreAllMocks();
});

describe("ErrorBoundary", () => {
  it("sin error renderiza los hijos", () => {
    render(<ErrorBoundary><p>contenido</p></ErrorBoundary>);
    expect(screen.getByText("contenido")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("hijo que lanza: muestra respaldo y Recargar, sin texto del error ni stack, y hace console.error", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { container } = render(<ErrorBoundary><Bomb /></ErrorBoundary>);
    expect(screen.getByRole("alert")).toHaveTextContent("Algo salió mal");
    expect(screen.getByRole("button", { name: "Recargar" })).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/kaboom secreto/);
    expect(container.textContent).not.toMatch(/\bat \w|Error:|\.jsx/);
    expect(spy).toHaveBeenCalled();
    expect(spy.mock.calls.some((c) => c.includes("Error de renderizado en la interfaz:"))).toBe(true);
  });

  it("Recargar llama a window.location.reload", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const reload = mockReload();
    render(<ErrorBoundary><Bomb /></ErrorBoundary>);
    await userEvent.click(screen.getByRole("button", { name: "Recargar" }));
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("mensaje de error con HTML hostil: no crea img ni se muestra", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { container } = render(<ErrorBoundary><Bomb msg="<img src=x onerror=alert(1)>" /></ErrorBoundary>);
    expect(container.querySelector("img")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
    expect(container.innerHTML).not.toMatch(/onerror/);
    expect(container.textContent).not.toMatch(/onerror|<img/);
  });

  it("no atrapa errores de eventos (comportamiento documentado de React)", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    // React reporta el error del handler al window; lo absorbemos para que no falle la corrida.
    const onWinErr = vi.fn((e) => e.preventDefault());
    window.addEventListener("error", onWinErr);
    try {
      render(
        <ErrorBoundary>
          <button onClick={() => { throw new Error("en el evento"); }}>Romper</button>
        </ErrorBoundary>,
      );
      await userEvent.click(screen.getByRole("button", { name: "Romper" }));
    } finally {
      window.removeEventListener("error", onWinErr);
    }
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Romper" })).toBeInTheDocument();
  });

  it("no tiene reset interno: el estado de error persiste aunque cambien los hijos (hay que recargar)", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { rerender } = render(<ErrorBoundary><Bomb /></ErrorBoundary>);
    rerender(<ErrorBoundary><p>ya sano</p></ErrorBoundary>);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText("ya sano")).toBeNull();
    expect(screen.getAllByRole("button")).toHaveLength(1); // solo Recargar
  });

  it("con una key nueva se remonta el boundary y renderiza de nuevo los hijos", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { rerender } = render(<ErrorBoundary key="a"><Bomb /></ErrorBoundary>);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    rerender(<ErrorBoundary key="b"><p>ya sano</p></ErrorBoundary>);
    expect(screen.getByText("ya sano")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
