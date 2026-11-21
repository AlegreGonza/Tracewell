import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import Toolbar from "./Toolbar.jsx";

const renderIt = (props = {}) =>
  render(<Toolbar busy={false} loaded={false} filters={{}} onDemo={vi.fn()} onAnalyze={vi.fn()} {...props} />);

describe("Toolbar: Informe HTML", () => {
  it("sin captura es un span deshabilitado, no un enlace ni un botón", () => {
    renderIt({ loaded: false });
    const el = screen.getByText("Informe HTML");
    expect(el.tagName).toBe("SPAN");
    expect(el).toHaveAttribute("aria-disabled", "true");
    expect(el).not.toHaveAttribute("href");
    expect(screen.queryByRole("link", { name: "Informe HTML" })).toBeNull();
  });

  it("con captura es un enlace de descarga a /api/report", () => {
    renderIt({ loaded: true });
    const a = screen.getByRole("link", { name: "Informe HTML" });
    expect(a).toHaveAttribute("href", "/api/report");
    expect(a).toHaveAttribute("download", "tracewell-informe.html");
  });

  it("el enlace del informe no arrastra los filtros activos", () => {
    renderIt({ loaded: true, filters: { ip: "10.0.0.1", protocol: "TCP" } });
    expect(screen.getByRole("link", { name: "Informe HTML" })).toHaveAttribute("href", "/api/report");
    expect(screen.getByRole("link", { name: "Exportar JSON" }).getAttribute("href")).toContain("ip=10.0.0.1");
  });

  it("convive con Exportar JSON en ambos estados", () => {
    const { rerender } = renderIt({ loaded: false });
    expect(screen.getByText("Exportar JSON")).toHaveAttribute("aria-disabled", "true");
    rerender(<Toolbar busy={false} loaded={true} filters={{}} onDemo={vi.fn()} onAnalyze={vi.fn()} />);
    expect(screen.getByRole("link", { name: "Exportar JSON" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Informe HTML" })).toBeInTheDocument();
  });

  it("sigue habilitado mientras está ocupada (solo es una descarga)", () => {
    renderIt({ loaded: true, busy: true });
    expect(screen.getByRole("link", { name: "Informe HTML" })).toBeInTheDocument();
  });
});
