import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Cada sección se reemplaza por un componente mínimo que cuenta cuántas veces se montó
const mounts = vi.hoisted(() => ({}));
vi.mock("../components/support/SystemOverview.jsx", () => ({ default: (p) => section("resumen", p) }));
vi.mock("../components/support/ProcessesView.jsx", () => ({ default: (p) => section("procesos", p) }));
vi.mock("../components/support/NetworkViews.jsx", () => ({ PortsView: (p) => section("puertos", p), ConnectionsView: (p) => section("conexiones", p) }));
vi.mock("../components/support/AutostartViews.jsx", () => ({ ServicesView: (p) => section("servicios", p), StartupView: (p) => section("inicio", p) }));
vi.mock("../components/support/NetConfigView.jsx", () => ({ default: (p) => section("config", p) }));
vi.mock("../components/support/InternetCheckView.jsx", () => ({ default: (p) => section("internet", p) }));
vi.mock("../components/support/LatencyView.jsx", () => ({ default: (p) => section("latencia", p) }));
vi.mock("../components/support/DevicesView.jsx", () => ({ default: (p) => section("dispositivos", p) }));
vi.mock("../components/support/WifiView.jsx", () => ({ default: (p) => section("wifi", p) }));
vi.mock("../components/support/MonitorView.jsx", () => ({ default: (p) => section("monitoreo", p) }));
vi.mock("../components/support/ToolsView.jsx", () => ({ default: (p) => section("herramientas", p) }));
import * as React from "react";
import SupportApp, { GROUPS } from "./SupportView.jsx";

function section(id, props) {
  React.useEffect(() => {
    mounts[id] = (mounts[id] ?? 0) + 1;
    return () => {
      mounts[`${id}-unmounted`] = (mounts[`${id}-unmounted`] ?? 0) + 1;
    };
  }, []);
  return <div data-testid={`sec-${id}`} data-active={String(props.active)}>sección {id}</div>;
}

beforeEach(() => {
  for (const k of Object.keys(mounts)) delete mounts[k];
});
const tab = (name) => screen.getByRole("tab", { name });
const sectionTabs = (group) => within(screen.getByRole("tablist", { name: `Secciones de ${group}` })).getAllByRole("tab");
const names = (tabs) => tabs.map((t) => t.textContent);
const present = () => screen.queryAllByTestId(/^sec-/).map((e) => e.getAttribute("data-testid"));

describe("SupportApp", () => {
  it("título y aviso de solo lectura", () => {
    render(<SupportApp />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Soporte de red");
    expect(screen.getByText(/de solo lectura: Tracewell mira tu equipo, no cambia ni termina nada/)).toBeInTheDocument();
    expect(screen.getByText(/requieren abrirlo como administrador/)).toBeInTheDocument();
  });

  it("dos grupos (Sistema | Red) con role=tab y aria-selected; empieza en Sistema", () => {
    render(<SupportApp />);
    const groups = within(screen.getByRole("tablist", { name: "Áreas de soporte" })).getAllByRole("tab");
    expect(names(groups)).toEqual(["Sistema", "Red"]);
    expect(groups.map((g) => g.getAttribute("aria-selected"))).toEqual(["true", "false"]);
    expect(GROUPS.map((g) => g.id)).toEqual(["sistema", "red"]);
  });

  it("Sistema tiene seis pestañas dentro de su tablist", () => {
    render(<SupportApp />);
    expect(names(sectionTabs("Sistema"))).toEqual(["Resumen", "Procesos", "Puertos abiertos", "Conexiones", "Servicios", "Programas de inicio"]);
  });

  it("Red tiene siete pestañas y empieza en Configuración", async () => {
    render(<SupportApp />);
    await userEvent.click(tab("Red"));
    expect(tab("Red")).toHaveAttribute("aria-selected", "true");
    expect(names(sectionTabs("Red"))).toEqual(["Configuración", "¿Hay Internet?", "Latencia", "Dispositivos", "Wi-Fi", "Monitoreo de cortes", "Herramientas"]);
    expect(present()).toEqual(["sec-config"]);
    expect(screen.getByText(/Pruebas de solo lectura: miden y explican/)).toBeInTheDocument();
  });

  it.each([["¿Hay Internet?", "sec-internet"], ["Latencia", "sec-latencia"], ["Dispositivos", "sec-dispositivos"], ["Wi-Fi", "sec-wifi"], ["Monitoreo de cortes", "sec-monitoreo"], ["Herramientas", "sec-herramientas"]])(
    "en Red, elegir %s monta solo esa sección", async (name, testId) => {
      render(<SupportApp />);
      await userEvent.click(tab("Red"));
      await userEvent.click(tab(name));
      expect(present()).toEqual([testId]);
    });

  it("cada grupo recuerda su sección al volver", async () => {
    render(<SupportApp />);
    await userEvent.click(tab("Procesos"));
    await userEvent.click(tab("Red"));
    await userEvent.click(tab("Wi-Fi"));
    await userEvent.click(tab("Sistema"));
    expect(present()).toEqual(["sec-procesos"]);
    await userEvent.click(tab("Red"));
    expect(present()).toEqual(["sec-wifi"]);
  });

  it("empieza en Resumen: solo esa pestaña del grupo tiene aria-selected=true y solo esa sección está montada", () => {
    render(<SupportApp />);
    const selected = sectionTabs("Sistema").filter((t) => t.getAttribute("aria-selected") === "true");
    expect(names(selected)).toEqual(["Resumen"]);
    expect(present()).toEqual(["sec-resumen"]);
  });

  it.each([["Procesos", "sec-procesos"], ["Puertos abiertos", "sec-puertos"], ["Conexiones", "sec-conexiones"], ["Servicios", "sec-servicios"], ["Programas de inicio", "sec-inicio"]])(
    "elegir %s monta solo esa sección", async (name, testId) => {
      render(<SupportApp />);
      await userEvent.click(tab(name));
      expect(present()).toEqual([testId]);
      expect(tab(name)).toHaveAttribute("aria-selected", "true");
      expect(tab("Resumen")).toHaveAttribute("aria-selected", "false");
    });

  it("la sección anterior se desmonta al cambiar", async () => {
    render(<SupportApp />);
    await userEvent.click(tab("Procesos"));
    expect(mounts["resumen-unmounted"]).toBe(1);
    expect(mounts.procesos).toBe(1);
  });

  it("las secciones que no se abrieron nunca se montan (no piden datos)", async () => {
    render(<SupportApp />);
    await userEvent.click(tab("Procesos"));
    expect(mounts.puertos).toBeUndefined();
    expect(mounts.conexiones).toBeUndefined();
    expect(mounts.servicios).toBeUndefined();
    expect(mounts.inicio).toBeUndefined();
  });

  it("volver a una sección la monta de nuevo (vuelve a pedir sus datos)", async () => {
    render(<SupportApp />);
    await userEvent.click(tab("Procesos"));
    await userEvent.click(tab("Resumen"));
    expect(mounts.resumen).toBe(2);
  });

  it("volver a clicar la misma pestaña no la vuelve a montar", async () => {
    render(<SupportApp />);
    await userEvent.click(tab("Resumen"));
    await userEvent.click(tab("Resumen"));
    expect(mounts.resumen).toBe(1);
  });

  it("le pasa a cada sección si la pantalla está activa (por defecto true)", async () => {
    const { rerender } = render(<SupportApp />);
    expect(screen.getByTestId("sec-resumen")).toHaveAttribute("data-active", "true");
    rerender(<SupportApp active={false} />);
    expect(screen.getByTestId("sec-resumen")).toHaveAttribute("data-active", "false");
    await userEvent.click(tab("Servicios"));
    expect(screen.getByTestId("sec-servicios")).toHaveAttribute("data-active", "false");
  });

  it("cambiar `active` no desmonta la sección", () => {
    const { rerender } = render(<SupportApp active />);
    rerender(<SupportApp active={false} />);
    rerender(<SupportApp active />);
    expect(mounts.resumen).toBe(1);
    expect(mounts["resumen-unmounted"]).toBeUndefined();
  });

  it("las pestañas se pueden operar con el teclado", async () => {
    render(<SupportApp />);
    tab("Conexiones").focus();
    await userEvent.keyboard("{Enter}");
    expect(present()).toEqual(["sec-conexiones"]);
    tab("Servicios").focus();
    await userEvent.keyboard(" ");
    expect(present()).toEqual(["sec-servicios"]);
  });

  it("todas las pestañas son botones type=button (no envían formularios)", () => {
    render(<SupportApp />);
    for (const t of screen.getAllByRole("tab")) expect(t).toHaveAttribute("type", "button");
  });

  it("ninguna pestaña ni botón ofrece acciones que modifiquen el sistema", () => {
    render(<SupportApp />);
    for (const b of [...screen.getAllByRole("tab"), ...screen.queryAllByRole("button")]) expect(b.textContent).not.toMatch(/termin|matar|kill|desactivar|borrar|apagar|reiniciar/i);
  });
});

describe("SupportApp: modo controlado (group y section)", () => {
  it("sin pestañas propias y con el título «Soporte de red · Grupo · Sección»", () => {
    render(<SupportApp group="red" section="wifi" />);
    expect(screen.queryAllByRole("tab")).toHaveLength(0);
    expect(screen.getByRole("heading", { level: 1 }).textContent.replace(/\s+/g, " ")).toBe("Soporte de red · Red · Wi-Fi");
    expect(present()).toEqual(["sec-wifi"]);
  });

  it("muestra la nota del grupo y cambia de sección al cambiar las props", () => {
    const { rerender } = render(<SupportApp group="sistema" section="procesos" />);
    expect(present()).toEqual(["sec-procesos"]);
    expect(screen.getByText(/de solo lectura: Tracewell mira tu equipo/)).toBeInTheDocument();
    rerender(<SupportApp group="red" section="latencia" />);
    expect(present()).toEqual(["sec-latencia"]);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Red · Latencia");
    expect(screen.getByText(/Pruebas de solo lectura: miden y explican/)).toBeInTheDocument();
  });

  it("una sección desconocida cae en la primera del grupo, y un grupo desconocido en Sistema", () => {
    const { rerender } = render(<SupportApp group="red" section="nada" />);
    expect(present()).toEqual(["sec-config"]);
    rerender(<SupportApp group="nada" section="nada" />);
    expect(present()).toEqual(["sec-resumen"]);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Sistema · Resumen");
  });

  it("pasa active a la sección", () => {
    render(<SupportApp active={false} group="sistema" section="resumen" />);
    expect(screen.getByTestId("sec-resumen")).toHaveAttribute("data-active", "false");
  });
});
