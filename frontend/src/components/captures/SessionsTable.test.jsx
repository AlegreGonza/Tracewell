import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";

vi.mock("../../api/client.js", () => ({ api: { sessions: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionsTable from "./SessionsTable.jsx";

const NONE = { protocol: "", ip: "", port: "" };
const sess = (id, over = {}) => ({
  id,
  protocol: "TCP",
  src_ip: "10.0.0.1",
  src_port: 1234,
  dst_ip: "fe80::1",
  dst_port: 443,
  packets: 12,
  bytes: 2048,
  first_ts: 1700000000,
  last_ts: 1700000002,
  duration: 2.5,
  ...over,
});
const page = (total, ids) => ({ total, items: ids.map((i) => sess(i)) });

let onError, onSelect, onFilters;

function Harness({ initial = NONE, refreshKey = 0 }) {
  const [filters, setFilters] = useState(initial);
  return (
    <SessionsTable
      refreshKey={refreshKey}
      filters={filters}
      onFilters={(f) => {
        onFilters(f);
        setFilters(f);
      }}
      selectedId={null}
      onSelect={onSelect}
    />
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  onSelect = vi.fn();
  onFilters = vi.fn();
  api.sessions.mockResolvedValue(page(2, [1, 2]));
});

const lastParams = () => api.sessions.mock.calls.at(-1)[0];

describe("SessionsTable", () => {
  it("renderiza filas con formateo", async () => {
    render(<Harness />);
    const row = (await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" })).closest("tr");
    expect(within(row).getByText("10.0.0.1:1234")).toBeInTheDocument();
    expect(within(row).getByText("[fe80::1]:443")).toBeInTheDocument();
    expect(within(row).getByText("2.00 KB")).toBeInTheDocument();
    expect(within(row).getByText("2.50 s")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("2 en total");
    expect(lastParams()).toEqual({ protocol: "", ip: "", port: "", limit: 25, offset: 0 });
  });

  it("onSelect al clickear el id", async () => {
    render(<Harness />);
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 2" }));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: 2 }));
  });

  it("los filtros se aplican AL ENVIAR, no por tecla", async () => {
    render(<Harness />);
    await screen.findByText("1");
    const calls = api.sessions.mock.calls.length;
    await userEvent.type(screen.getByLabelText("IP"), "10.0.0.9");
    await userEvent.type(screen.getByLabelText("Protocolo"), " tcp ");
    expect(onFilters).not.toHaveBeenCalled();
    expect(api.sessions).toHaveBeenCalledTimes(calls);
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    expect(onFilters).toHaveBeenCalledWith({ protocol: "tcp", ip: "10.0.0.9", port: "" });
    await vi.waitFor(() => expect(lastParams()).toMatchObject({ protocol: "tcp", ip: "10.0.0.9" }));
    expect(screen.getByRole("status")).toHaveTextContent("coinciden");
  });

  it("Limpiar deshabilitado sin filtros; al usarlo resetea todo", async () => {
    render(<Harness initial={{ protocol: "UDP", ip: "", port: "" }} />);
    await screen.findByText("1");
    const clear = screen.getByRole("button", { name: "Limpiar" });
    expect(clear).toBeEnabled();
    await userEvent.click(clear);
    expect(onFilters).toHaveBeenCalledWith(NONE);
    await vi.waitFor(() => expect(screen.getByRole("button", { name: "Limpiar" })).toBeDisabled());
    expect(screen.getByLabelText("Protocolo")).toHaveValue("");
  });

  it("paginación: Anterior/Siguiente con offset correcto", async () => {
    api.sessions.mockResolvedValue(page(60, [1, 2]));
    render(<Harness />);
    await screen.findByText("Página 1 de 3");
    const prev = screen.getByRole("button", { name: "Anterior" });
    const next = screen.getByRole("button", { name: "Siguiente" });
    expect(prev).toBeDisabled();
    await userEvent.click(next);
    await screen.findByText("Página 2 de 3");
    expect(lastParams().offset).toBe(25);
    await userEvent.click(next);
    await screen.findByText("Página 3 de 3");
    expect(lastParams().offset).toBe(50);
    expect(next).toBeDisabled();
    await userEvent.click(prev);
    await screen.findByText("Página 2 de 3");
    expect(lastParams().offset).toBe(25);
  });

  it("sin paginación si entra en una página", async () => {
    render(<Harness />);
    await screen.findByText("1");
    expect(screen.queryByRole("navigation")).toBeNull();
  });

  it("resetea a la página 0 al cambiar filtros", async () => {
    api.sessions.mockResolvedValue(page(60, [1]));
    render(<Harness />);
    await screen.findByText("Página 1 de 3");
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await screen.findByText("Página 2 de 3");
    await userEvent.type(screen.getByLabelText("Puerto"), "80");
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    await vi.waitFor(() => expect(screen.getByText("Página 1 de 3")).toBeInTheDocument());
    await vi.waitFor(() => expect(lastParams()).toMatchObject({ port: "80", offset: 0 }));
  });

  // Corregido: la página queda atada a los filtros
  it("no pide nunca la página vieja con los filtros nuevos", async () => {
    api.sessions.mockResolvedValue(page(60, [1]));
    render(<Harness />);
    await screen.findByText("Página 1 de 3");
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await screen.findByText("Página 2 de 3");
    api.sessions.mockClear();
    await userEvent.type(screen.getByLabelText("Puerto"), "80");
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    await vi.waitFor(() => expect(lastParams()).toMatchObject({ port: "80", offset: 0 }));
    const forNew = api.sessions.mock.calls.filter(([p]) => p.port === "80");
    expect(forNew.length).toBeGreaterThan(0);
    expect(forNew.every(([p]) => p.offset === 0)).toBe(true);
    // Orden completo: solo peticiones con los filtros nuevos y offset 0.
    expect(api.sessions.mock.calls.map(([p]) => `${p.port}:${p.offset}`)).toEqual(forNew.map(() => "80:0"));
  });

  it("filters vacío (estado normal) -> 'en total', no 'coinciden'", async () => {
    render(<Harness initial={NONE} />);
    await screen.findByText("1");
    expect(screen.getByRole("status")).toHaveTextContent("2 en total");
    expect(screen.getByRole("status")).not.toHaveTextContent("coinciden");
    expect(screen.getByRole("button", { name: "Limpiar" })).toBeDisabled();
  });

  it("filtros con valor -> 'coinciden'", async () => {
    render(<Harness initial={{ protocol: "UDP", ip: "", port: "" }} />);
    await screen.findByText("1");
    expect(screen.getByRole("status")).toHaveTextContent("2 coinciden");
    expect(screen.getByRole("status")).not.toHaveTextContent("en total");
  });

  it("cambiar refreshKey vuelve a pedir offset 0 sin pedir antes un offset viejo", async () => {
    api.sessions.mockResolvedValue(page(60, [1]));
    const { rerender } = render(<Harness refreshKey={0} />);
    await screen.findByText("Página 1 de 3");
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await screen.findByText("Página 2 de 3");
    expect(lastParams().offset).toBe(25);
    api.sessions.mockClear();
    rerender(<Harness refreshKey={1} />);
    await screen.findByText("Página 1 de 3");
    await vi.waitFor(() => expect(api.sessions).toHaveBeenCalled());
    expect(api.sessions.mock.calls.map(([p]) => p.offset)).toEqual([0]);
  });

  it("paginar y luego filtrar: el orden de llamadas nunca trae offset != 0 para los filtros nuevos", async () => {
    api.sessions.mockResolvedValue(page(60, [1]));
    render(<Harness />);
    await screen.findByText("Página 1 de 3");
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await userEvent.click(await screen.findByRole("button", { name: "Siguiente" }));
    await screen.findByText("Página 3 de 3");
    api.sessions.mockClear();
    await userEvent.type(screen.getByLabelText("IP"), "10.0.0.9");
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    await screen.findByText("Página 1 de 3");
    const order = api.sessions.mock.calls.map(([p]) => [p.ip, p.offset]);
    expect(order.length).toBeGreaterThan(0);
    expect(order.every(([ip, off]) => ip === "10.0.0.9" && off === 0)).toBe(true);
  });

  it("error de API: muestra 'No se pudo aplicar el filtro' y NO 'No hay sesiones'", async () => {
    api.sessions.mockRejectedValue(new Error("ip: inválida"));
    render(<Harness />);
    expect(await screen.findByText(/No se pudo aplicar el filtro: ip: inválida/)).toBeInTheDocument();
    expect(screen.queryByText(/No hay sesiones con esos criterios/)).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("—");
  });

  it("error de API: el aviso inline sale una sola vez y no hay banner ni callback de error", async () => {
    api.sessions.mockRejectedValue(new Error("ip: inválida"));
    render(<Harness />);
    await screen.findByText(/No se pudo aplicar el filtro: ip: inválida/);
    expect(screen.getAllByText(/ip: inválida/)).toHaveLength(1);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(onError).not.toHaveBeenCalled();
  });

  it("no depende de onError: sin la prop también muestra el aviso", async () => {
    api.sessions.mockRejectedValue(new Error("mal"));
    render(
      <SessionsTable refreshKey={0} filters={NONE} onFilters={vi.fn()} selectedId={null} onSelect={vi.fn()} />,
    );
    expect(await screen.findByText(/No se pudo aplicar el filtro: mal/)).toBeInTheDocument();
  });

  it("estado vacío legítimo muestra 'No hay sesiones con esos criterios.'", async () => {
    api.sessions.mockResolvedValue({ total: 0, items: [] });
    render(<Harness />);
    expect(await screen.findByText("No hay sesiones con esos criterios.")).toBeInTheDocument();
    expect(screen.queryByText(/No se pudo aplicar/)).toBeNull();
  });

  it("tras un error, una consulta exitosa limpia el aviso", async () => {
    api.sessions.mockRejectedValueOnce(new Error("mal"));
    render(<Harness />);
    await screen.findByText(/No se pudo aplicar el filtro/);
    api.sessions.mockResolvedValue(page(1, [7]));
    await userEvent.click(screen.getByRole("button", { name: "Filtrar" }));
    await screen.findByRole("button", { name: "Ver paquetes de la sesión 7" });
    expect(screen.queryByText(/No se pudo aplicar/)).toBeNull();
  });
});

describe("SessionsTable: dirección del flujo", () => {
  it("muestra la columna Dirección con la etiqueta de cada sesión", async () => {
    api.sessions.mockResolvedValue({ total: 2, items: [sess(1, { direction: "Interno→Externo" }), sess(2)] });
    render(<Harness />);
    expect(await screen.findByRole("columnheader", { name: "Dirección" })).toBeInTheDocument();
    expect(screen.getByText("Interno→Externo")).toBeInTheDocument();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0); // la sesión sin la clave (API vieja)
  });
});
