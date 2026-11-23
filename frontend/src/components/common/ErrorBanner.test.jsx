import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ErrorBanner from "./ErrorBanner.jsx";

describe("ErrorBanner", () => {
  it("null/vacío no renderiza nada", () => {
    const { container, rerender } = render(<ErrorBanner error={null} onClose={() => {}} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<ErrorBanner error="" onClose={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("muestra el mensaje con role=alert", () => {
    render(<ErrorBanner error="Algo salió mal" onClose={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Algo salió mal");
  });

  it("cerrar llama onClose", async () => {
    const onClose = vi.fn();
    render(<ErrorBanner error="x" onClose={onClose} />);
    await userEvent.click(screen.getByRole("button", { name: "Cerrar aviso" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("el mensaje se muestra como texto, no como HTML", () => {
    const { container } = render(<ErrorBanner error="<img src=x onerror=alert(1)>" onClose={() => {}} />);
    expect(container.querySelector("img")).toBeNull();
  });
});
