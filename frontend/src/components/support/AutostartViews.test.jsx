import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { systemServices: vi.fn(), systemStartup: vi.fn() } }));
import { api } from "../../api/client.js";
import { ServicesView, StartupView } from "./AutostartViews.jsx";

const rowsOf = (c) => Array.from(c.querySelectorAll("tbody tr"));
const cellsOf = (tr) => Array.from(tr.querySelectorAll("td")).map((c) => c.textContent);
const HINT = { code: "carpeta_temporal", text: "Corre desde una carpeta temporal." };

// =================================================================== ServicesView
const svc = (name, over = {}) => ({ name, display: `Servicio ${name}`, status: "running", start: "Automático", pid: 1, user: "SYSTEM", path: `C:\\x\\${name}.exe`, hints: [], ...over });
const services = (items, over = {}) => ({ supported: true, total: items.length, items, ...over });

describe("ServicesView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.systemServices.mockResolvedValue(services([svc("a"), svc("b", { status: "stopped", hints: [HINT] }), svc("c", { display: null, start: null, user: null, path: null })]));
  });
  const show = (props = {}) => render(<ServicesView active {...props} />);
  const loaded = async () => {
    const r = show();
    await screen.findByRole("heading", { name: "Servicios" });
    return r;
  };

  it("pide los servicios con una señal y muestra 'Leyendo…' mientras carga", () => {
    api.systemServices.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Leyendo los servicios…")).toBeInTheDocument();
    expect(api.systemServices).toHaveBeenCalledWith(expect.any(AbortSignal));
  });

  it("'Solo los que están en marcha' viene activado: los detenidos no se ven", async () => {
    const { container } = await loaded();
    expect(screen.getByLabelText("Solo los que están en marcha")).toBeChecked();
    expect(rowsOf(container).map((r) => cellsOf(r)[0])).toEqual(["Servicio a", "c"]);
  });

  it("desactivar el filtro muestra todos", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo los que están en marcha"));
    expect(rowsOf(container)).toHaveLength(3);
  });

  it("encabezados y fila completa", async () => {
    const { container } = await loaded();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Servicio", "Estado", "Arranque", "Cuenta", "Programa", "Pistas"]);
    expect(cellsOf(rowsOf(container)[0])).toEqual(["Servicio a", "running", "Automático", "SYSTEM", "C:\\x\\a.exe", ""]);
  });

  it("sin nombre para mostrar usa el nombre interno; sin datos '—'", async () => {
    const { container } = await loaded();
    const cells = cellsOf(rowsOf(container)[1]);
    expect(cells[0]).toBe("c");
    expect(cells.slice(2, 5)).toEqual(["—", "—", "—"]);
    expect(rowsOf(container)[1].querySelector("td")).toHaveAttribute("title", "c");
  });

  it("el total del encabezado cuenta todos los servicios, no solo los visibles", async () => {
    await loaded();
    expect(screen.getByText("3 servicios")).toBeInTheDocument();
  });

  it("pistas con nombre corto y motivo como tooltip", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo los que están en marcha"));
    const chip = container.querySelector(".note-chip");
    expect(chip).toHaveTextContent("Carpeta temporal");
    expect(chip).toHaveAttribute("title", HINT.text);
  });

  it.each([["servicio a", ["Servicio a"]], ["SYSTEM", ["Servicio a", "Servicio b"]], ["x\\a", ["Servicio a"]], ["b.exe", ["Servicio b"]]])("buscar %j (sin el filtro de en marcha)", async (q, expected) => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo los que están en marcha"));
    await userEvent.type(screen.getByLabelText("Buscar"), q);
    expect(rowsOf(container).map((r) => cellsOf(r)[0])).toEqual(expected);
  });

  it("buscar sin resultados: 'Nada para mostrar.'", async () => {
    await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "zzz");
    expect(screen.getByText("Nada para mostrar.")).toBeInTheDocument();
  });

  it("plataforma sin soporte: aviso con la razón, sin tabla ni total", async () => {
    api.systemServices.mockResolvedValue({ supported: false, reason: "Los servicios solo se listan en Windows y en Linux con systemd.", total: 0, items: [] });
    show();
    expect(await screen.findByRole("note")).toHaveTextContent("Los servicios solo se listan en Windows y en Linux con systemd.");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("un error se muestra como alerta", async () => {
    api.systemServices.mockRejectedValue(new Error("falta psutil"));
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("falta psutil");
  });

  it("Actualizar vuelve a pedir", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    await waitFor(() => expect(api.systemServices).toHaveBeenCalledTimes(2));
  });

  it("datos hostiles como texto y sin botones que modifiquen", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.systemServices.mockResolvedValue(services([svc("a", { display: evil, user: evil, path: evil, hints: [{ code: evil, text: evil }] })]));
    const { container } = await loaded();
    expect(container.querySelector("img")).toBeNull();
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/detener|iniciar|desactivar|activar|reiniciar|eliminar|borrar/i);
  });

  it("tiene botón de ayuda", async () => {
    await loaded();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
  });
});

// =================================================================== StartupView
const item = (name, over = {}) => ({ where: "Inicio de tu usuario", name, command: `C:\\apps\\${name}.exe --x`, hints: [], ...over });
const startup = (items, over = {}) => ({ supported: true, total: items.length, items, ...over });

describe("StartupView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.systemStartup.mockResolvedValue(startup([item("Spotify"), item("Evil", { where: "Inicio de todos los usuarios", hints: [HINT] })]));
  });
  const show = (props = {}) => render(<StartupView active {...props} />);
  const loaded = async () => {
    const r = show();
    await screen.findByRole("heading", { name: "Programas de inicio" });
    return r;
  };

  it("'Leyendo…' mientras carga y pide con señal", () => {
    api.systemStartup.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Leyendo el inicio…")).toBeInTheDocument();
    expect(api.systemStartup).toHaveBeenCalledWith(expect.any(AbortSignal));
  });

  it("encabezados y filas", async () => {
    const { container } = await loaded();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Nombre", "Dónde está anotado", "Se ejecuta", "Pistas"]);
    expect(cellsOf(rowsOf(container)[0])).toEqual(["Spotify", "Inicio de tu usuario", "C:\\apps\\Spotify.exe --x", ""]);
    expect(rowsOf(container)).toHaveLength(2);
  });

  it("pistas visibles con su nombre corto", async () => {
    const { container } = await loaded();
    expect(container.querySelector(".note-chip")).toHaveTextContent("Carpeta temporal");
  });

  it("plataforma sin soporte: muestra la razón y ninguna tabla", async () => {
    api.systemStartup.mockResolvedValue({ supported: false, reason: "Los programas de inicio solo se listan en Windows y Linux.", total: 0, items: [] });
    show();
    expect(await screen.findByRole("note")).toHaveTextContent("Los programas de inicio solo se listan en Windows y Linux.");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("soportado pero vacío: mensaje", async () => {
    api.systemStartup.mockResolvedValue(startup([]));
    await loaded();
    expect(screen.getByText("No hay programas de inicio registrados.")).toBeInTheDocument();
  });

  it("un error se muestra como alerta", async () => {
    api.systemStartup.mockRejectedValue(new Error("no se pudo leer"));
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("no se pudo leer");
  });

  it("Actualizar vuelve a pedir y se deshabilita mientras carga", async () => {
    await loaded();
    let resolve;
    api.systemStartup.mockReturnValue(new Promise((r) => (resolve = r)));
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    expect(screen.getByRole("button", { name: "Actualizar" })).toBeDisabled();
    resolve(startup([item("Nuevo")]));
    expect(await screen.findByText("Nuevo")).toBeInTheDocument();
  });

  it("dos entradas con el mismo nombre y lugar no chocan", async () => {
    api.systemStartup.mockResolvedValue(startup([item("Dup"), item("Dup")]));
    const { container } = await loaded();
    expect(rowsOf(container)).toHaveLength(2);
  });

  it("comandos y nombres hostiles o enormes se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.systemStartup.mockResolvedValue(startup([item(evil, { command: evil + "x".repeat(400), where: evil })]));
    const { container } = await loaded();
    expect(container.querySelector("img")).toBeNull();
  });

  it("no ofrece desactivar ni borrar entradas", async () => {
    await loaded();
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/desactivar|borrar|eliminar|quitar|deshabilitar/i);
  });

  it("tiene ayuda", async () => {
    await loaded();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
  });
});
