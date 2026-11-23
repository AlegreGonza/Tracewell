import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { systemProcesses: vi.fn(), systemProcess: vi.fn(), systemProcessFile: vi.fn() } }));
import { api } from "../../api/client.js";
import ProcessesView from "./ProcessesView.jsx";

const row = (pid, over = {}) => ({
  pid, ppid: 1, name: `prog${pid}.exe`, user: "ana", cpu: 1.5, rss: 50 * 1024 * 1024, threads: 4, status: "running", started: 1700000000,
  exe: `C:\\Program Files\\prog${pid}.exe`, cmdline: "x", connections: 0, hints: [], ...over,
});
const HINT = { code: "carpeta_temporal", text: "Corre desde una carpeta temporal." };
const list = (items, over = {}) => ({ total: items.length, ncpu: 8, items, ...over });
const detail = (pid, over = {}) => ({
  pid, name: `prog${pid}.exe`, exe: `C:\\x\\prog${pid}.exe`, user: "ana", status: "running", cmdline: "prog --x", cwd: "C:\\x", started: 1700000000, threads: 2,
  rss: 1024, vms: 2048, parent: null, children: [], io: null, hints: [], open_files: [], modules: [], connections: [], ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  api.systemProcesses.mockResolvedValue(list([row(1, { rss: 300 * 1024 * 1024 }), row(2, { name: "chrome.exe", user: "root", exe: "/usr/bin/chrome", hints: [HINT], connections: 3 }), row(3, { name: null, cpu: null, rss: null, user: null, exe: null })]));
  api.systemProcess.mockImplementation(async (pid) => detail(pid));
});
afterEach(() => vi.useRealTimers());

const show = (props = {}) => render(<ProcessesView active {...props} />);
const loaded = async () => {
  const r = show();
  await screen.findByRole("heading", { name: "Procesos" });
  return r;
};
const rows = (c) => Array.from(c.querySelectorAll("tbody tr"));
const names = (c) => rows(c).map((r) => r.querySelector("td")?.textContent);

describe("ProcessesView", () => {
  it("al montarse pide los procesos ordenados por RAM con un límite de 600 y una señal", async () => {
    await loaded();
    expect(api.systemProcesses).toHaveBeenCalledTimes(1);
    expect(api.systemProcesses).toHaveBeenCalledWith({ sort: "ram", limit: 600 }, expect.any(AbortSignal));
  });

  it("'Leyendo los procesos…' mientras carga", () => {
    api.systemProcesses.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Leyendo los procesos…")).toBeInTheDocument();
  });

  it("encabezados, filas y resumen con pistas", async () => {
    const { container } = await loaded();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Nombre", "PID", "Usuario", "RAM", "Procesador", "Conexiones", "Pistas"]);
    expect(rows(container)).toHaveLength(3);
    expect(screen.getByText("3 en marcha · 1 con pistas")).toBeInTheDocument();
    const cells = Array.from(rows(container)[0].querySelectorAll("td")).map((c) => c.textContent);
    expect(cells).toEqual(["prog1.exe", "1", "ana", "300.0 MB", "1.5 %", "0", ""]);
  });

  it("valores desconocidos se muestran como '—' y el nombre ausente como 'PID n'", async () => {
    const { container } = await loaded();
    const cells = Array.from(rows(container)[2].querySelectorAll("td")).map((c) => c.textContent);
    expect(cells).toEqual(["PID 3", "3", "—", "—", "—", "0", ""]);
    expect(rows(container)[2].querySelector("button")).toHaveAttribute("title", "Ruta no disponible");
  });

  it("el nombre lleva como tooltip la ruta del programa", async () => {
    await loaded();
    expect(screen.getByRole("button", { name: "chrome.exe" })).toHaveAttribute("title", "/usr/bin/chrome");
  });

  it("las pistas se muestran con su nombre corto y el motivo como tooltip", async () => {
    const { container } = await loaded();
    const chip = container.querySelector(".note-chip");
    expect(chip).toHaveTextContent("Carpeta temporal");
    expect(chip).toHaveAttribute("title", HINT.text);
  });

  it("una pista desconocida muestra su código", async () => {
    api.systemProcesses.mockResolvedValue(list([row(1, { hints: [{ code: "nueva_pista", text: "t" }] })]));
    await loaded();
    expect(screen.getByText("nueva_pista")).toBeInTheDocument();
  });

  // ---- búsqueda y filtros
  it.each([["chrome", ["chrome.exe"]], ["CHROME", ["chrome.exe"]], ["/usr/bin", ["chrome.exe"]], ["root", ["chrome.exe"]], ["prog1", ["prog1.exe"]], ["1", ["prog1.exe"]]])(
    "buscar %j filtra por nombre, ruta, usuario o PID", async (q, expected) => {
      const { container } = await loaded();
      await userEvent.type(screen.getByLabelText("Buscar"), q);
      expect(names(container)).toEqual(expected);
    });

  it("la búsqueda ignora espacios alrededor y no vuelve a pedir al servidor", async () => {
    const { container } = await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "  chrome  ");
    expect(names(container)).toEqual(["chrome.exe"]);
    expect(api.systemProcesses).toHaveBeenCalledTimes(1);
  });

  it("sin coincidencias: mensaje", async () => {
    await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "zzz-nada");
    expect(screen.getByText("Ningún proceso coincide con la búsqueda.")).toBeInTheDocument();
  });

  it("caracteres especiales en la búsqueda no rompen", async () => {
    await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "(.*[[");
    expect(screen.getByText("Ningún proceso coincide con la búsqueda.")).toBeInTheDocument();
  });

  it("'Solo con pistas' deja únicamente los que traen pistas", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo con pistas"));
    expect(names(container)).toEqual(["chrome.exe"]);
    await userEvent.click(screen.getByLabelText("Solo con pistas"));
    expect(rows(container)).toHaveLength(3);
  });

  it("los filtros se combinan", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo con pistas"));
    await userEvent.type(screen.getByLabelText("Buscar"), "prog");
    expect(screen.getByText("Ningún proceso coincide con la búsqueda.")).toBeInTheDocument();
    expect(rows(container)).toHaveLength(1);
  });

  // ---- orden
  it("las opciones de orden son RAM, procesador, nombre y PID", async () => {
    await loaded();
    const select = screen.getByLabelText("Ordenar por");
    expect(within(select).getAllByRole("option").map((o) => o.value)).toEqual(["ram", "cpu", "name", "pid"]);
    expect(select).toHaveValue("ram");
  });

  it("cambiar el orden vuelve a pedir al servidor con ese orden", async () => {
    await loaded();
    await userEvent.selectOptions(screen.getByLabelText("Ordenar por"), "cpu");
    await waitFor(() => expect(api.systemProcesses).toHaveBeenCalledTimes(2));
    expect(api.systemProcesses).toHaveBeenLastCalledWith({ sort: "cpu", limit: 600 }, expect.any(AbortSignal));
    expect(api.systemProcesses.mock.calls[0][1].aborted).toBe(true);
    await userEvent.selectOptions(screen.getByLabelText("Ordenar por"), "name");
    await waitFor(() => expect(api.systemProcesses).toHaveBeenLastCalledWith({ sort: "name", limit: 600 }, expect.any(AbortSignal)));
    await userEvent.selectOptions(screen.getByLabelText("Ordenar por"), "pid");
    await waitFor(() => expect(api.systemProcesses).toHaveBeenLastCalledWith({ sort: "pid", limit: 600 }, expect.any(AbortSignal)));
  });

  it("cambiar filtros de texto no cambia el pedido", async () => {
    await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "a");
    await userEvent.click(screen.getByLabelText("Solo con pistas"));
    expect(api.systemProcesses).toHaveBeenCalledTimes(1);
  });

  // ---- actualizar
  it("el botón Actualizar vuelve a pedir", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    await waitFor(() => expect(api.systemProcesses).toHaveBeenCalledTimes(2));
  });

  it("'Actualizar cada 5 s' está apagado al principio: no hay recarga automática", async () => {
    vi.useFakeTimers();
    show();
    await act(async () => {});
    expect(screen.getByLabelText("Actualizar cada 5 s")).not.toBeChecked();
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(api.systemProcesses).toHaveBeenCalledTimes(1);
  });

  it("al activarlo recarga cada 5 s y al apagarlo para", async () => {
    vi.useFakeTimers();
    show();
    await act(async () => {});
    await act(async () => { screen.getByLabelText("Actualizar cada 5 s").click(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(api.systemProcesses).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(api.systemProcesses).toHaveBeenCalledTimes(3);
    await act(async () => { screen.getByLabelText("Actualizar cada 5 s").click(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(api.systemProcesses).toHaveBeenCalledTimes(3);
  });

  it("con active=false (pantalla oculta) el auto-refresco no corre aunque esté activado", async () => {
    vi.useFakeTimers();
    show({ active: false });
    await act(async () => {});
    await act(async () => { screen.getByLabelText("Actualizar cada 5 s").click(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(api.systemProcesses).toHaveBeenCalledTimes(1);
  });

  it("un error se muestra como alerta (y la pantalla no se rompe)", async () => {
    api.systemProcesses.mockRejectedValue(new Error("Falta la librería psutil"));
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("Falta la librería psutil");
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByRole("button", { name: "Actualizar" })).toBeInTheDocument();
  });

  it("si la recarga falla, se conserva la tabla anterior y aparece el error", async () => {
    const { container } = await loaded();
    api.systemProcesses.mockRejectedValue(new Error("se cayó"));
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("se cayó");
    expect(rows(container)).toHaveLength(3);
  });

  it("lista vacía: tabla sin filas y mensaje", async () => {
    api.systemProcesses.mockResolvedValue(list([]));
    await loaded();
    expect(screen.getByText("Ningún proceso coincide con la búsqueda.")).toBeInTheDocument();
    expect(screen.getByText("0 en marcha · 0 con pistas")).toBeInTheDocument();
  });

  // ---- seguridad / solo lectura
  it("nunca hay botones para terminar, matar, suspender ni cambiar prioridad", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "chrome.exe" }));
    await screen.findByRole("complementary", { name: "Proceso 2" });
    for (const b of screen.getAllByRole("button")) expect(b.textContent + (b.getAttribute("aria-label") ?? "")).not.toMatch(/termin|matar|kill|finaliz|detener|suspend|prioridad|cerrar proceso/i);
  });

  it("nombre, ruta y usuario hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.systemProcesses.mockResolvedValue(list([row(1, { name: evil, user: evil, exe: evil, hints: [{ code: evil, text: evil }] })]));
    const { container } = await loaded();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByRole("button", { name: evil })).toHaveAttribute("title", evil);
  });

  it("rutas raras (con espacios, unicode, UNC) se ven tal cual", async () => {
    const weird = "\\\\servidor\\compartida\\ñandú — copia (2)\\a b.exe";
    api.systemProcesses.mockResolvedValue(list([row(1, { exe: weird })]));
    await loaded();
    expect(screen.getByRole("button", { name: "prog1.exe" })).toHaveAttribute("title", weird);
  });

  it("tiene su botón de ayuda", async () => {
    await loaded();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
  });

  // ---- detalle
  it("nada de detalle hasta que se elige un proceso", async () => {
    const { container } = await loaded();
    expect(screen.queryByRole("complementary")).toBeNull();
    expect(api.systemProcess).not.toHaveBeenCalled();
    expect(container.firstChild.className).toBe("layout");
  });

  it("clic en un nombre abre el detalle de ese PID y cambia el diseño", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "chrome.exe" }));
    expect(await screen.findByRole("complementary", { name: "Proceso 2" })).toBeInTheDocument();
    expect(api.systemProcess).toHaveBeenCalledWith(2, expect.any(AbortSignal));
    expect(container.firstChild.className).toBe("layout with-detail");
    expect(rows(container)[1].className).toBe("selected");
  });

  it("cerrar el detalle vuelve al diseño normal", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "chrome.exe" }));
    await screen.findByRole("complementary");
    await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
    expect(screen.queryByRole("complementary")).toBeNull();
    expect(container.firstChild.className).toBe("layout");
  });

  it("elegir otro proceso cambia el detalle", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "chrome.exe" }));
    await screen.findByRole("complementary", { name: "Proceso 2" });
    await userEvent.click(screen.getByRole("button", { name: "prog1.exe" }));
    expect(await screen.findByRole("complementary", { name: "Proceso 1" })).toBeInTheDocument();
  });

  it("recargar la lista no cierra el detalle abierto", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "chrome.exe" }));
    await screen.findByRole("complementary");
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    await waitFor(() => expect(api.systemProcesses).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("complementary")).toBeInTheDocument();
  });
});
