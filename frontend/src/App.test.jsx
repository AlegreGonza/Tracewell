import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import * as React from "react";

// Las dos pantallas se reemplazan por componentes mínimos que registran sus props y cuántas veces se montaron.
const log = vi.hoisted(() => ({ app: 0, appUnmounts: 0, support: 0, supportUnmounts: 0, captures: null, support_props: null }));
vi.mock("./views/CapturesView.jsx", () => ({
  default: function FakeCaptures(props) {
    const [n, setN] = React.useState(0);
    log.captures = props;
    React.useEffect(() => {
      log.app += 1;
      return () => {
        log.appUnmounts += 1;
      };
    }, []);
    return (
      <div data-testid="app">
        <span data-testid="section">{props.section}</span>
        <button type="button" onClick={() => setN((v) => v + 1)}>contar {n}</button>
        <button type="button" onClick={() => props.onNavigate("sesiones")}>ir a sesiones</button>
        <button type="button" onClick={props.onOpenSupport}>abrir soporte</button>
        <input aria-label="ruta" />
      </div>
    );
  },
}));
vi.mock("./views/SupportView.jsx", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    default: function FakeSupport(props) {
      log.support_props = props;
      React.useEffect(() => {
        log.support += 1;
        return () => {
          log.supportUnmounts += 1;
        };
      }, []);
      return <div data-testid="support">soporte {props.group}/{props.section} {String(props.active)}</div>;
    },
  };
});
import Shell, { CAPTURE_SECTIONS } from "./App.jsx";

beforeEach(() => {
  Object.assign(log, { app: 0, appUnmounts: 0, support: 0, supportUnmounts: 0, captures: null, support_props: null });
});
const nav = () => screen.getByRole("navigation", { name: "Secciones de Tracewell" });
const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// El nombre accesible de un item puede llevar al final la insignia numérica (p. ej. «Alertas y ATT&CK3»).
const item = (name) => within(nav()).getByRole("button", { name: new RegExp(`^${esc(name)}\\s*\\d*$`) });
const wrapper = (testId) => screen.getByTestId(testId).parentElement;
const summary = (over = {}) => ({ source: "demo.pcap", alerts: 3, stats: { packets: 4500 }, ...over });

describe("Shell: marco y navegación", () => {
  it("marca Tracewell, barra lateral con los dos grupos y todas las secciones", () => {
    render(<Shell />);
    expect(screen.getByText("Tracewell")).toBeInTheDocument();
    expect(CAPTURE_SECTIONS.map((s) => s.id)).toEqual(["panorama", "alertas", "equipos", "trafico", "remoto", "sesiones", "indicadores"]);
    ["Panorama", "Alertas y ATT&CK", "Equipos", "DNS y HTTP", "Sesiones", "Indicadores (IOC)"].forEach((l) =>
      expect(item(l)).toHaveAttribute("type", "button")
    );
    expect(within(nav()).getByText("Capturas")).toBeInTheDocument();
    expect(within(nav()).getByText("Soporte de red")).toBeInTheDocument();
    expect(item("Sistema")).toBeInTheDocument();
    expect(item("Red")).toBeInTheDocument();
  });

  it("al principio: Panorama activo (aria-current) y CapturesView recibe section=panorama", () => {
    render(<Shell />);
    expect(item("Panorama")).toHaveAttribute("aria-current", "page");
    expect(item("Equipos")).not.toHaveAttribute("aria-current");
    expect(screen.getByTestId("section")).toHaveTextContent("panorama");
    expect(wrapper("app")).not.toHaveAttribute("hidden");
  });

  it("cambiar de sección se la pasa a CapturesView y mueve aria-current", async () => {
    render(<Shell />);
    await userEvent.click(item("DNS y HTTP"));
    expect(screen.getByTestId("section")).toHaveTextContent("trafico");
    expect(item("DNS y HTTP")).toHaveAttribute("aria-current", "page");
    expect(item("Panorama")).not.toHaveAttribute("aria-current");
    await userEvent.click(item("Indicadores (IOC)"));
    expect(screen.getByTestId("section")).toHaveTextContent("indicadores");
    expect(log.app).toBe(1);
    expect(log.appUnmounts).toBe(0);
  });

  it("onNavigate de CapturesView cambia la sección", async () => {
    render(<Shell />);
    await userEvent.click(screen.getByRole("button", { name: "ir a sesiones" }));
    expect(screen.getByTestId("section")).toHaveTextContent("sesiones");
    expect(item("Sesiones")).toHaveAttribute("aria-current", "page");
  });

  it("onNavigate desde Soporte vuelve a Capturas", async () => {
    render(<Shell />);
    await userEvent.click(item("Procesos"));
    act(() => log.captures.onNavigate("alertas"));
    expect(wrapper("app")).not.toHaveAttribute("hidden");
    expect(wrapper("support")).toHaveAttribute("hidden");
    expect(item("Alertas y ATT&CK")).toHaveAttribute("aria-current", "page");
    expect(item("Procesos")).not.toHaveAttribute("aria-current");
  });
});

describe("Shell: captura cargada (onCapture)", () => {
  it("sin captura no hay chip ni insignia", () => {
    render(<Shell />);
    expect(screen.queryByText(/paquetes/)).toBeNull();
    expect(within(item("Alertas y ATT&CK")).queryByText("3")).toBeNull();
  });

  it("con captura el chip muestra archivo y paquetes, y la insignia las alertas", () => {
    render(<Shell />);
    act(() => log.captures.onCapture(summary()));
    expect(screen.getByText(/demo\.pcap · 4\.500 paquetes|demo\.pcap · 4,500 paquetes|demo\.pcap · 4500 paquetes/)).toBeInTheDocument();
    expect(within(item("Alertas y ATT&CK")).getByText("3")).toBeInTheDocument();
  });

  it("sin alertas no hay insignia; con stats incompletas el chip no falla", () => {
    render(<Shell />);
    act(() => log.captures.onCapture(summary({ alerts: 0, stats: undefined })));
    expect(screen.getByText(/demo\.pcap · — paquetes/)).toBeInTheDocument();
    expect(within(item("Alertas y ATT&CK")).queryByText("0")).toBeNull();
  });

  it("al cerrar la captura (null) desaparece el chip", () => {
    render(<Shell />);
    act(() => log.captures.onCapture(summary()));
    act(() => log.captures.onCapture(null));
    expect(screen.queryByText(/paquetes/)).toBeNull();
  });

  it("el nombre de archivo hostil se ve como texto", () => {
    const evil = "<script>alert(1)</script>.pcap";
    const { container } = render(<Shell />);
    act(() => log.captures.onCapture(summary({ source: evil })));
    expect(screen.getByText(new RegExp(evil.replace(/[()]/g, "\\$&")))).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });

  it("Abrir soporte de red desde la entrada abre Sistema > Resumen", async () => {
    render(<Shell />);
    await userEvent.click(screen.getByRole("button", { name: "abrir soporte" }));
    expect(screen.getByTestId("support")).toHaveTextContent("sistema/resumen");
    expect(item("Resumen")).toHaveAttribute("aria-current", "page");
  });
});

describe("Shell: Soporte de red", () => {
  it("SupportView NO se monta hasta que se abre por primera vez", () => {
    render(<Shell />);
    expect(screen.queryByTestId("support")).toBeNull();
    expect(log.support).toBe(0);
  });

  it("los grupos son desplegables: Sistema empieza abierto con sus seis secciones", () => {
    render(<Shell />);
    ["Resumen", "Procesos", "Puertos abiertos", "Conexiones", "Servicios", "Programas de inicio"].forEach((l) =>
      expect(item(l)).toBeVisible()
    );
  });

  it("Red se despliega con sus siete secciones", async () => {
    render(<Shell />);
    await userEvent.click(item("Red"));
    for (const l of ["Configuración", "¿Hay Internet?", "Latencia", "Dispositivos", "Wi-Fi", "Monitoreo de cortes", "Herramientas"]) {
      expect(await within(nav()).findByRole("button", { name: l })).toBeInTheDocument();
    }
  });

  it("elegir una sección monta SupportView con group/section, oculta Capturas sin desmontarla y marca aria-current", async () => {
    render(<Shell />);
    await userEvent.click(item("Puertos abiertos"));
    expect(screen.getByTestId("support")).toHaveTextContent("sistema/puertos true");
    expect(log.support_props).toMatchObject({ group: "sistema", section: "puertos", active: true });
    expect(wrapper("app")).toHaveAttribute("hidden");
    expect(wrapper("support")).not.toHaveAttribute("hidden");
    expect(item("Puertos abiertos")).toHaveAttribute("aria-current", "page");
    expect(item("Panorama")).not.toHaveAttribute("aria-current");
    expect(log.appUnmounts).toBe(0);
    expect(log.support).toBe(1);
  });

  it("de un grupo a otro cambia group y section", async () => {
    render(<Shell />);
    await userEvent.click(item("Red"));
    await userEvent.click(await within(nav()).findByRole("button", { name: "Wi-Fi" }));
    expect(log.support_props).toMatchObject({ group: "red", section: "wifi" });
  });

  it("volver a Capturas conserva su estado y deja Soporte montado pero oculto e inactivo", async () => {
    render(<Shell />);
    await userEvent.click(screen.getByRole("button", { name: "contar 0" }));
    await userEvent.type(screen.getByLabelText("ruta"), "captura.pcap");
    await userEvent.click(item("Procesos"));
    await userEvent.click(item("Equipos"));
    expect(screen.getByRole("button", { name: "contar 1" })).toBeVisible();
    expect(screen.getByLabelText("ruta")).toHaveValue("captura.pcap");
    expect(log.app).toBe(1);
    expect(log.appUnmounts).toBe(0);
    expect(screen.getByTestId("support")).toBeInTheDocument();
    expect(wrapper("support")).toHaveAttribute("hidden");
    expect(log.support_props.active).toBe(false);
    expect(log.supportUnmounts).toBe(0);
    await userEvent.click(item("Procesos"));
    expect(log.support).toBe(1);
    expect(log.support_props.active).toBe(true);
  });

  it("ir y venir muchas veces no remonta nada", async () => {
    render(<Shell />);
    for (let i = 0; i < 4; i++) {
      await userEvent.click(item("Conexiones"));
      await userEvent.click(item("Panorama"));
    }
    expect(log.app).toBe(1);
    expect(log.support).toBe(1);
    expect(log.appUnmounts + log.supportUnmounts).toBe(0);
  });
});

describe("Shell: apariencia", () => {
  it("el botón «Cambiar la apariencia» abre un menú con las tres paletas y marca la actual", async () => {
    render(<Shell palette="violeta" onPalette={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Cambiar la apariencia" }));
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((i) => i.textContent.trim())).toEqual(["Esmeralda", "Violeta", "Terracota"]);
    expect(items[1].querySelector("svg")).not.toBeNull(); // tilde de la paleta actual
    expect(items[0].querySelector("svg")).toBeNull();
    expect(items[2].querySelector("svg")).toBeNull();
  });

  it("elegir una paleta llama a onPalette con su id", async () => {
    const onPalette = vi.fn();
    render(<Shell onPalette={onPalette} />);
    await userEvent.click(screen.getByRole("button", { name: "Cambiar la apariencia" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Terracota" }));
    expect(onPalette).toHaveBeenCalledWith("terracota");
  });

  it("sin onPalette elegir una paleta no rompe", async () => {
    render(<Shell />);
    await userEvent.click(screen.getByRole("button", { name: "Cambiar la apariencia" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Violeta" }));
    expect(screen.getByText("Tracewell")).toBeInTheDocument();
  });

  it("el menú ofrece el modo Auto / Claro / Oscuro", async () => {
    render(<Shell />);
    await userEvent.click(screen.getByRole("button", { name: "Cambiar la apariencia" }));
    for (const m of ["Auto", "Claro", "Oscuro"]) expect(await screen.findByText(m)).toBeInTheDocument();
    await userEvent.click(screen.getByText("Oscuro"));
    expect(screen.getByRole("radio", { name: "Oscuro" })).toBeChecked();
  });
});
