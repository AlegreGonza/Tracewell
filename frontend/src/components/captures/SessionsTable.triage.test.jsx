import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { sessions: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionsTable, { PAGE_SIZE } from "./SessionsTable.jsx";

const NONE = { protocol: "", ip: "", port: "" };
const sess = (id, over = {}) => ({
  id, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80,
  packets: 1, bytes: 10, first_ts: 1, last_ts: 2, duration: 1, ...over,
});
const XSS = "<script>alert(1)</script><img src=x onerror=alert(2)>";

let onSelect;
beforeEach(() => {
  vi.clearAllMocks();
  onSelect = vi.fn();
  api.sessions.mockResolvedValue({ total: 1, items: [sess(1)] });
});

const renderIt = (props = {}) =>
  render(<SessionsTable refreshKey={0} filters={NONE} onFilters={vi.fn()} selectedId={null} onSelect={onSelect} {...props} />);
const rowOf = async (id) => (await screen.findByRole("button", { name: `Ver paquetes de la sesión ${id}` })).closest("tr");

describe("SessionsTable: marcas de triaje", () => {
  it("sin anotaciones ni IOC no hay marcas", async () => {
    renderIt();
    const row = await rowOf(1);
    expect(within(row).queryByText("✓")).toBeNull();
    expect(within(row).queryByText("nota")).toBeNull();
    expect(within(row).queryByText("IOC")).toBeNull();
  });

  it("revisada muestra ✓ con título", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { reviewed: true })] });
    renderIt();
    const mark = within(await rowOf(1)).getByText("✓");
    expect(mark).toHaveAttribute("title", "Marcada como revisada");
  });

  it("nota muestra 'nota' con el texto completo en el title", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { note: "keep-alive conocido", reviewed: false })] });
    renderIt();
    const row = await rowOf(1);
    expect(within(row).getByText("nota")).toHaveAttribute("title", "keep-alive conocido");
    expect(within(row).queryByText("✓")).toBeNull();
  });

  it("revisada con nota vacía muestra solo ✓", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { reviewed: true, note: "" })] });
    renderIt();
    const row = await rowOf(1);
    expect(within(row).getByText("✓")).toBeInTheDocument();
    expect(within(row).queryByText("nota")).toBeNull();
  });

  it("IOC muestra la insignia con los indicadores en el title", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { ioc: ["ip:10.0.0.2", "red:10.0.0.0/8"] })] });
    renderIt();
    const badge = within(await rowOf(1)).getByText("IOC");
    expect(badge).toHaveAttribute("title", "Coincide con: ip:10.0.0.2, red:10.0.0.0/8");
  });

  it("ioc vacío no muestra insignia", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { ioc: [] })] });
    renderIt();
    expect(within(await rowOf(1)).queryByText("IOC")).toBeNull();
  });

  it("las tres marcas juntas", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { reviewed: true, note: "n", ioc: ["ip:1.1.1.1"] })] });
    renderIt();
    const row = await rowOf(1);
    ["✓", "nota", "IOC"].forEach((t) => expect(within(row).getByText(t)).toBeInTheDocument());
  });

  it("una nota hostil solo vive en el atributo title: ningún nodo inyectado", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { note: XSS, ioc: [XSS] })] });
    const { container } = renderIt();
    const row = await rowOf(1);
    expect(within(row).getByText("nota")).toHaveAttribute("title", XSS);
    expect(within(row).getByText("IOC")).toHaveAttribute("title", `Coincide con: ${XSS}`);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(row.textContent).not.toContain("alert(1)");
  });

  it("las marcas no impiden seleccionar la sesión", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { note: "x" })] });
    renderIt();
    await userEvent.click(await screen.findByRole("button", { name: "Ver paquetes de la sesión 1" }));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: 1, note: "x" }));
  });
});

describe("SessionsTable: triageVersion", () => {
  const many = (n, start = 0) => Array.from({ length: n }, (_, i) => sess(start + i));

  it("al subir triageVersion vuelve a pedir la misma página sin volver a la primera", async () => {
    api.sessions.mockImplementation(async (p) => ({ total: 60, items: many(PAGE_SIZE, p.offset) }));
    const { rerender } = renderIt({ triageVersion: 0 });
    await screen.findByText(/en total/);
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await vi.waitFor(() => expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ offset: PAGE_SIZE }));
    await screen.findByText("Página 2 de 3");
    const before = api.sessions.mock.calls.length;

    api.sessions.mockImplementation(async (p) => ({ total: 60, items: many(PAGE_SIZE, p.offset).map((s) => ({ ...s, note: "nueva" })) }));
    rerender(
      <SessionsTable refreshKey={0} triageVersion={1} filters={NONE} onFilters={vi.fn()} selectedId={null} onSelect={onSelect} />,
    );
    await vi.waitFor(() => expect(api.sessions.mock.calls.length).toBe(before + 1));
    expect(api.sessions.mock.calls.at(-1)[0]).toMatchObject({ offset: PAGE_SIZE, limit: PAGE_SIZE });
    expect(screen.getByText("Página 2 de 3")).toBeInTheDocument();
    expect((await screen.findAllByText("nota")).length).toBe(PAGE_SIZE);
  });

  it("sin cambios en triageVersion no se vuelve a pedir", async () => {
    const { rerender } = renderIt({ triageVersion: 3 });
    await rowOf(1);
    const calls = api.sessions.mock.calls.length;
    rerender(<SessionsTable refreshKey={0} triageVersion={3} filters={NONE} onFilters={vi.fn()} selectedId={null} onSelect={onSelect} />);
    await Promise.resolve();
    expect(api.sessions.mock.calls.length).toBe(calls);
  });

  it("refreshKey sí vuelve a la primera página (análisis nuevo)", async () => {
    api.sessions.mockImplementation(async (p) => ({ total: 60, items: many(PAGE_SIZE, p.offset) }));
    const { rerender } = renderIt();
    await screen.findByText(/en total/);
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await screen.findByText("Página 2 de 3");
    rerender(<SessionsTable refreshKey={1} filters={NONE} onFilters={vi.fn()} selectedId={null} onSelect={onSelect} />);
    await screen.findByText("Página 1 de 3");
  });
});
