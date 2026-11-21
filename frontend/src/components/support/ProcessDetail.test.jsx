import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { systemProcess: vi.fn(), systemProcessFile: vi.fn() } }));
import { api } from "../../api/client.js";
import ProcessDetail from "./ProcessDetail.jsx";

const detail = (pid, over = {}) => ({
  pid, name: "app.exe", exe: "C:\\Program Files\\app.exe", user: "ana", status: "running", cmdline: "app.exe --x", cwd: "C:\\work", started: 1700000000, threads: 3,
  rss: 5 * 1024 * 1024, vms: 9 * 1024 * 1024, parent: { pid: 1, name: "init" }, children: [{ pid: 30, name: "hijo" }, { pid: 31, name: null }], io: { read: 2048, written: 1024 },
  hints: [], open_files: ["/a/b.txt"], modules: ["/lib/x.so", "/lib/y.so"],
  connections: [{ local: "10.0.0.5:4000", remote: "8.8.8.8:443", status: "ESTABLISHED", owner: "Google" }, { local: "0.0.0.0:80", remote: null, status: "LISTEN", owner: null }], ...over,
});
const FILE = { available: true, path: "C:\\Program Files\\app.exe", size: 2048, sha256: "ab".repeat(32), signature: { status: "Valid", text: "Firma válida: el programa lo firmó su autor y no fue modificado.", subject: "CN=Acme" } };

let onClose, onSelect;
beforeEach(() => {
  vi.clearAllMocks();
  onClose = vi.fn();
  onSelect = vi.fn();
  api.systemProcess.mockImplementation(async (pid) => detail(pid));
  api.systemProcessFile.mockResolvedValue(FILE);
});
const show = (props = {}) => render(<ProcessDetail pid={7} onClose={onClose} onSelect={onSelect} {...props} />);
const loaded = async (props) => {
  const r = show(props);
  await screen.findByText("app.exe");
  return r;
};

describe("ProcessDetail", () => {
  it("encabezado con el PID, pide el detalle con señal y mientras tanto dice 'Leyendo…'", async () => {
    api.systemProcess.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByRole("complementary", { name: "Proceso 7" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Proceso 7" })).toBeInTheDocument();
    expect(screen.getByText("Leyendo…")).toBeInTheDocument();
    expect(api.systemProcess).toHaveBeenCalledWith(7, expect.any(AbortSignal));
  });

  it("muestra los datos del proceso", async () => {
    const { container } = await loaded();
    const t = container.textContent;
    for (const s of ["C:\\Program Files\\app.exe", "app.exe --x", "C:\\work", "ana", "running · 3 hilos", "5.00 MB en uso · 9.00 MB reservados", "2.00 KB / 1.00 KB"]) expect(t).toContain(s);
  });

  it("'Cerrar' llama a onClose", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Cerrar" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("datos que el sistema no deja ver: guiones y explicaciones", async () => {
    api.systemProcess.mockResolvedValue(detail(7, { exe: null, cmdline: null, cwd: null, user: null, started: null, status: null, threads: null, rss: null, vms: null, io: null,
      parent: null, children: [], open_files: [], modules: [], connections: [] }));
    const { container } = show();
    await screen.findByText("app.exe");
    const t = container.textContent;
    expect(t).toContain("— (sin permiso para verlo)");
    expect(t).toContain("— (ya no existe o no se puede ver)");
    expect(t).toContain("Sin conexiones de red abiertas (o no se pueden ver).");
    expect(screen.queryByText(/Disco leído/)).toBeNull();
    expect(screen.queryByText(/Bibliotecas cargadas/)).toBeNull();
    expect(screen.queryByText(/Archivos abiertos/)).toBeNull();
    expect(screen.queryByText(/Lanzó a/)).toBeNull();
  });

  it("proceso sin nombre muestra '—' como título", async () => {
    api.systemProcess.mockResolvedValue(detail(7, { name: null }));
    const { container } = show();
    await waitFor(() => expect(container.querySelector(".big")).toHaveTextContent("—"));
  });

  it("pistas: un aviso role=note por cada una, con su nombre y motivo", async () => {
    api.systemProcess.mockResolvedValue(detail(7, { hints: [{ code: "carpeta_temporal", text: "Corre desde una carpeta temporal." }, { code: "borrado", text: "El archivo ya no está." }] }));
    show();
    const notes = await screen.findAllByRole("note");
    expect(notes).toHaveLength(2);
    expect(notes[0]).toHaveTextContent("Carpeta temporal. Corre desde una carpeta temporal.");
    expect(notes[1]).toHaveTextContent("Archivo borrado. El archivo ya no está.");
  });

  it("sin pistas no hay avisos", async () => {
    await loaded();
    expect(screen.queryByRole("note")).toBeNull();
  });

  // ---- navegación
  it("el padre es un botón que llama a onSelect con su PID", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "init (1)" }));
    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("los hijos son botones; uno sin nombre muestra '?'", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "hijo (30)" }));
    expect(onSelect).toHaveBeenLastCalledWith(30);
    await userEvent.click(screen.getByRole("button", { name: "? (31)" }));
    expect(onSelect).toHaveBeenLastCalledWith(31);
  });

  it("padre sin nombre", async () => {
    api.systemProcess.mockResolvedValue(detail(7, { parent: { pid: 4, name: null } }));
    show();
    expect(await screen.findByRole("button", { name: "? (4)" })).toBeInTheDocument();
  });

  // ---- huella y firma
  it("no calcula la huella hasta que se pide con el botón", async () => {
    await loaded();
    expect(api.systemProcessFile).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Ver huella y firma del archivo" })).toBeInTheDocument();
    expect(screen.getByText(/Solo lee el archivo del disco; no lo envía a ningún lado\./)).toBeInTheDocument();
  });

  it("el botón pide la huella del PID una vez y muestra tamaño, SHA-256 y firma", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    expect(await screen.findByText("ab".repeat(32))).toBeInTheDocument();
    expect(api.systemProcessFile).toHaveBeenCalledTimes(1);
    expect(api.systemProcessFile).toHaveBeenCalledWith(7);
    const t = container.querySelector(".file-check").textContent;
    expect(t).toContain("2.00 KB");
    expect(t).toContain("Firma válida: el programa lo firmó su autor y no fue modificado.");
    expect(t).toContain("CN=Acme");
  });

  it("mientras verifica el botón dice 'Verificando…' y está deshabilitado", async () => {
    await loaded();
    let resolve;
    api.systemProcessFile.mockReturnValue(new Promise((r) => (resolve = r)));
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    const busy = screen.getByRole("button", { name: "Verificando…" });
    expect(busy).toBeDisabled();
    resolve(FILE);
    expect(await screen.findByRole("button", { name: "Ver huella y firma del archivo" })).toBeEnabled();
  });

  it("archivo no disponible: muestra el motivo", async () => {
    api.systemProcessFile.mockResolvedValue({ available: false, reason: "No se pudo leer la ruta del programa (puede faltar permiso de administrador)." });
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    expect(await screen.findByText(/puede faltar permiso de administrador/)).toBeInTheDocument();
    expect(screen.queryByText("SHA-256")).toBeNull();
  });

  it("sin hash: muestra la nota (por ejemplo, archivo demasiado grande) y '—' sin tamaño", async () => {
    api.systemProcessFile.mockResolvedValue({ available: true, size: null, sha256: null, hash_note: "El archivo es demasiado grande para calcular la huella acá.", signature: null });
    const { container } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    expect(await screen.findByText(/demasiado grande/)).toBeInTheDocument();
    expect(container.querySelector(".file-check").textContent).toContain("Tamaño—");
  });

  it("sin firma ni nota muestra '—'", async () => {
    api.systemProcessFile.mockResolvedValue({ available: true, size: 1, sha256: null, signature: null });
    const { container } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    await waitFor(() => expect(container.querySelector(".file-check dl")).not.toBeNull());
    expect(container.querySelector(".file-check").textContent).toContain("SHA-256—");
  });

  it("firma sin sujeto: no dibuja la línea del sujeto", async () => {
    api.systemProcessFile.mockResolvedValue({ ...FILE, signature: { status: "NotSigned", text: "Sin firma.", subject: null } });
    const { container } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    await screen.findByText("Sin firma.");
    expect(container.querySelector(".file-check dd .muted")).toBeNull();
  });

  it("un error al pedir la huella se muestra como alerta y se puede reintentar", async () => {
    api.systemProcessFile.mockRejectedValueOnce(new Error("503: falta psutil"));
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("503: falta psutil");
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    expect(await screen.findByText("ab".repeat(32))).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("al cambiar de proceso se descarta la huella anterior y se pide el detalle nuevo", async () => {
    const { rerender } = await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    await screen.findByText("ab".repeat(32));
    rerender(<ProcessDetail pid={8} onClose={onClose} onSelect={onSelect} />);
    await waitFor(() => expect(api.systemProcess).toHaveBeenLastCalledWith(8, expect.any(AbortSignal)));
    await waitFor(() => expect(screen.queryByText("ab".repeat(32))).toBeNull());
    expect(api.systemProcessFile).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("heading", { name: "Proceso 8" })).toBeInTheDocument();
  });

  // ---- listas
  it("conexiones con propietario, 'escuchando' y contador", async () => {
    await loaded();
    expect(screen.getByRole("heading", { name: "Conexiones (2)" })).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5:4000 → 8.8.8.8:443 · ESTABLISHED · Google")).toBeInTheDocument();
    expect(screen.getByText("0.0.0.0:80 (escuchando) · LISTEN")).toBeInTheDocument();
  });

  it("bibliotecas y archivos abiertos en secciones plegables", async () => {
    const { container } = await loaded();
    const details = container.querySelectorAll("details");
    expect(details).toHaveLength(2);
    expect(details[0].querySelector("summary")).toHaveTextContent("Bibliotecas cargadas (2)");
    expect(details[1].querySelector("summary")).toHaveTextContent("Archivos abiertos (1)");
    expect(details[0].open).toBe(false);
    await userEvent.click(details[0].querySelector("summary"));
    expect(details[0].open).toBe(true);
    expect(screen.getByText("/lib/x.so")).toBeInTheDocument();
  });

  it("errores: alerta y sin datos", async () => {
    api.systemProcess.mockRejectedValue(new Error("el proceso no existe (o ya terminó)"));
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("el proceso no existe");
    expect(screen.queryByText("Línea de comandos")).toBeNull();
  });

  it("al desmontar aborta el pedido", () => {
    api.systemProcess.mockReturnValue(new Promise(() => {}));
    const { unmount } = show();
    const signal = api.systemProcess.mock.calls[0][1];
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it("cuando cambia el PID aborta el pedido anterior", async () => {
    api.systemProcess.mockReturnValue(new Promise(() => {}));
    const { rerender } = show();
    const first = api.systemProcess.mock.calls[0][1];
    rerender(<ProcessDetail pid={9} onClose={onClose} onSelect={onSelect} />);
    await waitFor(() => expect(first.aborted).toBe(true));
  });

  // ---- seguridad
  it("nunca ofrece acciones que modifiquen el proceso", async () => {
    await loaded();
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/termin|matar|kill|finaliz|detener|suspend|prioridad|borrar|eliminar/i);
  });

  it("todo dato del sistema hostil se muestra como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.systemProcess.mockResolvedValue(detail(7, {
      name: evil, exe: evil, cmdline: evil, cwd: evil, user: evil, status: evil, parent: { pid: 1, name: evil }, children: [{ pid: 2, name: evil }],
      hints: [{ code: evil, text: evil }], open_files: [evil], modules: [evil], connections: [{ local: evil, remote: evil, status: evil, owner: evil }],
    }));
    api.systemProcessFile.mockResolvedValue({ ...FILE, sha256: evil, signature: { status: "x", text: evil, subject: evil } });
    const { container } = show();
    await screen.findByRole("heading", { name: "Conexiones (1)" });
    await userEvent.click(screen.getByRole("button", { name: "Ver huella y firma del archivo" }));
    await waitFor(() => expect(container.querySelector(".file-check dl")).not.toBeNull());
    expect(container.querySelector("img")).toBeNull();
  });

  it("rutas y comandos raros (comillas, espacios, unicode) se ven completos", async () => {
    const cmd = '"C:\\Program Files\\Ñandú\\a b.exe" --arg="x y" `whoami` $(calc)';
    api.systemProcess.mockResolvedValue(detail(7, { cmdline: cmd, exe: "\\\\srv\\share\\a b.exe" }));
    const { container } = show();
    await screen.findByText("app.exe");
    expect(container.textContent).toContain(cmd);
    expect(container.textContent).toContain("\\\\srv\\share\\a b.exe");
  });
});
