import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { systemPorts: vi.fn(), systemConnections: vi.fn() } }));
import { api } from "../../api/client.js";
import { ConnectionsView, PortsView } from "./NetworkViews.jsx";

afterEach(() => vi.useRealTimers());
const rowsOf = (c) => Array.from(c.querySelectorAll("tbody tr"));
const cellsOf = (tr) => Array.from(tr.querySelectorAll("td")).map((c) => c.textContent);

// =================================================================== PortsView
const port = (over = {}) => ({
  proto: "TCP", ip: "0.0.0.0", port: 80, pid: 10, process: "nginx", exposure: "todas", exposure_text: "Toda la red", service: "HTTP", ...over,
});
const ports = (items, over = {}) => ({ total: items.length, items, limited: false, ...over });

describe("PortsView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.systemPorts.mockResolvedValue(ports([
      port(),
      port({ ip: "127.0.0.1", port: 5432, process: "postgres", pid: 20, exposure: "local", exposure_text: "Solo esta PC", service: null }),
      port({ proto: "UDP", ip: "192.168.1.5", port: 5353, process: null, pid: null, exposure: "especifica", exposure_text: "Una dirección concreta", service: "mDNS" }),
    ]));
  });
  const show = (props = {}) => render(<PortsView active {...props} />);
  const loaded = async () => {
    const r = show();
    await screen.findByRole("heading", { name: "Puertos abiertos" });
    return r;
  };

  it("pide los puertos con señal de aborto al montarse y muestra 'Leyendo…' mientras tanto", async () => {
    api.systemPorts.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Leyendo los puertos…")).toBeInTheDocument();
    expect(api.systemPorts).toHaveBeenCalledWith(expect.any(AbortSignal));
  });

  it("encabezados, filas y resumen", async () => {
    const { container } = await loaded();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Puerto", "Protocolo", "Servicio", "Quién puede llamar", "Dirección", "Programa"]);
    expect(rowsOf(container)).toHaveLength(3);
    expect(screen.getByText("3 en escucha · 1 abiertos a toda la red")).toBeInTheDocument();
    expect(cellsOf(rowsOf(container)[0])).toEqual(["80", "TCP", "HTTP", "Toda la red", "0.0.0.0", "nginx (10)"]);
  });

  it("servicio o programa desconocidos se muestran como '—'", async () => {
    const { container } = await loaded();
    expect(cellsOf(rowsOf(container)[1])[2]).toBe("—");
    expect(cellsOf(rowsOf(container)[2])[5]).toBe("—");
  });

  it("la exposición lleva clase según el alcance", async () => {
    const { container } = await loaded();
    expect(Array.from(container.querySelectorAll(".expo")).map((e) => e.className)).toEqual(["expo expo-all", "expo expo-local", "expo expo-some"]);
  });

  it("exposición desconocida no rompe", async () => {
    api.systemPorts.mockResolvedValue(ports([port({ exposure: "rara", exposure_text: "Rara" })]));
    const { container } = await loaded();
    expect(container.querySelector(".expo").className.trim()).toBe("expo");
  });

  it("'Solo abiertos a toda la red' filtra por exposición", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo abiertos a toda la red"));
    expect(rowsOf(container)).toHaveLength(1);
    expect(cellsOf(rowsOf(container)[0])[0]).toBe("80");
  });

  it.each([["postgres", "5432"], ["HTTP", "80"], ["5353", "5353"], ["127.0.0.1", "5432"], ["MDNS", "5353"], ["NGINX", "80"]])("buscar %j encuentra el puerto %s", async (q, expected) => {
    const { container } = await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), q);
    expect(rowsOf(container).map((r) => cellsOf(r)[0])).toEqual([expected]);
  });

  it("buscar sin resultados: 'Nada para mostrar.'", async () => {
    await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "zzz");
    expect(screen.getByText("Nada para mostrar.")).toBeInTheDocument();
  });

  it("filtros y búsqueda se combinan y no vuelven a pedir al servidor", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo abiertos a toda la red"));
    await userEvent.type(screen.getByLabelText("Buscar"), "postgres");
    expect(rowsOf(container).map((r) => r.textContent)).toEqual(["Nada para mostrar."]);
    expect(api.systemPorts).toHaveBeenCalledTimes(1);
  });

  it("limited=true muestra un aviso (role=note) sobre permisos de administrador", async () => {
    api.systemPorts.mockResolvedValue(ports([port({ pid: null, process: null })], { limited: true }));
    show();
    expect(await screen.findByRole("note")).toHaveTextContent("Sin permisos de administrador no se ve qué programa tiene cada puerto");
  });

  it("limited=false no muestra el aviso", async () => {
    await loaded();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("un error se muestra como alerta", async () => {
    api.systemPorts.mockRejectedValue(new Error("falta psutil"));
    show();
    expect(await screen.findByRole("alert")).toHaveTextContent("falta psutil");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("Actualizar vuelve a pedir; no se actualiza solo", async () => {
    vi.useFakeTimers();
    show();
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(api.systemPorts).toHaveBeenCalledTimes(1);
    await act(async () => { screen.getByRole("button", { name: "Actualizar" }).click(); });
    expect(api.systemPorts).toHaveBeenCalledTimes(2);
  });

  it("lista vacía", async () => {
    api.systemPorts.mockResolvedValue(ports([]));
    await loaded();
    expect(screen.getByText("Nada para mostrar.")).toBeInTheDocument();
    expect(screen.getByText("0 en escucha · 0 abiertos a toda la red")).toBeInTheDocument();
  });

  it("programa y servicio hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.systemPorts.mockResolvedValue(ports([port({ process: evil, service: evil, ip: evil, exposure_text: evil })]));
    const { container } = await loaded();
    expect(container.querySelector("img")).toBeNull();
  });

  it("tiene ayuda y ningún botón que modifique (no hay 'cerrar puerto')", async () => {
    await loaded();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/cerrar puerto|bloquear|terminar|matar|abrir puerto/i);
  });

  it("al desmontar aborta el pedido", () => {
    api.systemPorts.mockReturnValue(new Promise(() => {}));
    const { unmount } = show();
    const signal = api.systemPorts.mock.calls[0][0];
    unmount();
    expect(signal.aborted).toBe(true);
  });
});

// =================================================================== ConnectionsView
const connRow = (over = {}) => ({
  pid: 10, process: "chrome.exe", local: "192.168.1.5:50000", remote: "142.250.1.1:443", remote_ip: "142.250.1.1", status: "ESTABLISHED",
  owner: "Google", scope: "publica", service: "HTTPS", ...over,
});
const conns = (items) => ({ total: items.length, items });

describe("ConnectionsView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.systemConnections.mockResolvedValue(conns([
      connRow(),
      connRow({ process: "sshd", pid: 20, local: "10.0.0.5:22", remote: "10.0.0.9:50000", remote_ip: "10.0.0.9", owner: null, scope: "interna", service: null }),
      connRow({ process: null, pid: null, remote: "93.184.216.34:80", remote_ip: "93.184.216.34", owner: null, scope: "publica", service: "HTTP", status: "TIME_WAIT" }),
    ]));
  });
  const show = (props = {}) => render(<ConnectionsView active {...props} />);
  const loaded = async () => {
    const r = show();
    await screen.findByRole("heading", { name: "Conexiones activas" });
    return r;
  };

  it("pide las conexiones al montarse", async () => {
    await loaded();
    expect(api.systemConnections).toHaveBeenCalledWith(expect.any(AbortSignal));
  });

  it("'Leyendo…' mientras carga", () => {
    api.systemConnections.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Leyendo las conexiones…")).toBeInTheDocument();
  });

  it("encabezados, filas y resumen", async () => {
    const { container } = await loaded();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Programa", "Desde", "Hacia", "Servicio", "Dueño del rango", "Estado"]);
    expect(screen.getByText("3 conexiones (se actualiza cada 5 s)")).toBeInTheDocument();
    expect(cellsOf(rowsOf(container)[0])).toEqual(["chrome.exe (10)", "192.168.1.5:50000", "142.250.1.1:443", "HTTPS", "Google", "ESTABLISHED"]);
  });

  it("sin dueño: 'desconocido' si es pública y 'red local' si no; sin programa '—'", async () => {
    const { container } = await loaded();
    expect(cellsOf(rowsOf(container)[1])[4]).toBe("red local");
    expect(cellsOf(rowsOf(container)[2])[4]).toBe("desconocido");
    expect(cellsOf(rowsOf(container)[2])[0]).toBe("—");
    expect(cellsOf(rowsOf(container)[1])[3]).toBe("—");
  });

  it("'Solo hacia internet' deja las de alcance público", async () => {
    const { container } = await loaded();
    await userEvent.click(screen.getByLabelText("Solo hacia internet"));
    expect(rowsOf(container)).toHaveLength(2);
    expect(rowsOf(container).every((r) => !cellsOf(r)[2].startsWith("10."))).toBe(true);
  });

  it.each([["chrome", 1], ["google", 1], ["93.184", 1], ["https", 1], ["sshd", 1], ["HTTP", 2], ["nada-aqui", 0]])("buscar %j da %i filas", async (q, n) => {
    const { container } = await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), q);
    const found = rowsOf(container).filter((r) => r.querySelectorAll("td").length > 1);
    expect(found).toHaveLength(n);
  });

  it("sin resultados: 'Nada para mostrar.'", async () => {
    await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "zzz");
    expect(screen.getByText("Nada para mostrar.")).toBeInTheDocument();
  });

  it("se actualiza sola cada 5 s si está activa", async () => {
    vi.useFakeTimers();
    show({ active: true });
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(api.systemConnections).toHaveBeenCalledTimes(2);
  });

  it("no se actualiza sola si la pantalla no está activa", async () => {
    vi.useFakeTimers();
    show({ active: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(api.systemConnections).toHaveBeenCalledTimes(1);
  });

  it("Actualizar vuelve a pedir", async () => {
    await loaded();
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    await waitFor(() => expect(api.systemConnections).toHaveBeenCalledTimes(2));
  });

  it("un error se muestra como alerta; si había tabla, se conserva", async () => {
    const { container } = await loaded();
    api.systemConnections.mockRejectedValue(new Error("se cayó"));
    await userEvent.click(screen.getByRole("button", { name: "Actualizar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("se cayó");
    expect(rowsOf(container)).toHaveLength(3);
  });

  it("lista vacía", async () => {
    api.systemConnections.mockResolvedValue(conns([]));
    await loaded();
    expect(screen.getByText("Nada para mostrar.")).toBeInTheDocument();
    expect(screen.getByText("0 conexiones (se actualiza cada 5 s)")).toBeInTheDocument();
  });

  it("datos hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.systemConnections.mockResolvedValue(conns([connRow({ process: evil, remote: evil, owner: evil, service: evil, status: evil, local: evil })]));
    const { container } = await loaded();
    expect(container.querySelector("img")).toBeNull();
  });

  it("limited con total 0: aviso (role=note) sobre permisos de administrador", async () => {
    api.systemConnections.mockResolvedValue({ total: 0, items: [], limited: true });
    await loaded();
    expect(screen.getByRole("note")).toHaveTextContent("El sistema no deja listar las conexiones sin permisos de administrador");
    expect(screen.getByText("Nada para mostrar.")).toBeInTheDocument();
  });

  it("sin limited, o con limited pero con filas, no hay aviso", async () => {
    await loaded();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("limited=true con filas (no debería pasar) no muestra el aviso", async () => {
    api.systemConnections.mockResolvedValue({ ...conns([connRow()]), limited: true });
    await loaded();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("limited=false y total 0: sin aviso", async () => {
    api.systemConnections.mockResolvedValue({ total: 0, items: [], limited: false });
    await loaded();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("local y remoto nulos (IP ilegible) se muestran como '—'", async () => {
    api.systemConnections.mockResolvedValue(conns([connRow({ local: null, remote: null, remote_ip: null, owner: null, scope: null })]));
    const { container } = await loaded();
    const cells = cellsOf(rowsOf(container)[0]);
    expect(cells[1]).toBe("—");
    expect(cells[2]).toBe("—");
    expect(container.textContent).not.toContain("None");
    expect(container.textContent).not.toContain("null");
  });

  it("buscar no rompe cuando remote es null", async () => {
    api.systemConnections.mockResolvedValue(conns([connRow({ remote: null, remote_ip: null }), connRow({ process: "ssh" })]));
    const { container } = await loaded();
    await userEvent.type(screen.getByLabelText("Buscar"), "ssh");
    expect(rowsOf(container)).toHaveLength(1);
  });

  it("tiene ayuda y no ofrece cortar conexiones", async () => {
    await loaded();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
    for (const b of screen.getAllByRole("button")) expect(b.textContent).not.toMatch(/cortar|bloquear|terminar|cerrar conexi/i);
  });
});
