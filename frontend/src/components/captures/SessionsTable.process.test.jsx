import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({ api: { sessions: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionsTable from "./SessionsTable.jsx";

const NONE = { protocol: "", ip: "", port: "" };
const sess = (id, over = {}) => ({
  id, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 443,
  packets: 1, bytes: 10, first_ts: 1, last_ts: 2, duration: 1, ...over,
});

const show = (props = {}) =>
  render(
    <SessionsTable refreshKey={0} filters={NONE} onFilters={() => {}} selectedId={null} onSelect={() => {}} {...props} />,
  );
const rowOf = async (id) => (await screen.findByRole("button", { name: `Ver paquetes de la sesión ${id}` })).closest("tr");

beforeEach(() => vi.clearAllMocks());

describe("SessionsTable columna Proceso", () => {
  it("sin showProcess no hay columna ni celda", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 4, name: "x.exe" } })] });
    show();
    const row = await rowOf(1);
    expect(screen.queryByRole("columnheader", { name: "Proceso" })).toBeNull();
    expect(within(row).queryByText("x.exe")).toBeNull();
    expect(within(row).getAllByRole("cell")).toHaveLength(7);
  });

  it("con showProcess muestra cabecera y nombre con title PID", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 4321, name: "chrome.exe" } })] });
    show({ showProcess: true });
    const row = await rowOf(1);
    expect(screen.getByRole("columnheader", { name: "Proceso" })).toBeInTheDocument();
    const cell = within(row).getByText("chrome.exe");
    expect(cell).toHaveAttribute("title", "PID 4321");
    expect(cell).toHaveClass("mono");
    expect(within(row).getAllByRole("cell")).toHaveLength(8);
  });

  it("process null o ausente muestra raya con title explicativo", async () => {
    api.sessions.mockResolvedValue({ total: 2, items: [sess(1, { process: null }), sess(2)] });
    show({ showProcess: true });
    for (const id of [1, 2]) {
      const row = await rowOf(id);
      const dash = within(row).getByText("—");
      expect(dash.tagName).toBe("TD");
      expect(dash.getAttribute("title")).toMatch(/identificar/);
    }
  });

  it("un nombre hostil se renderiza como texto, nunca como HTML", async () => {
    const hostile = "<img src=x onerror=alert(1)>";
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 1, name: hostile } })] });
    const { container } = show({ showProcess: true });
    const row = await rowOf(1);
    expect(within(row).getByText(hostile).textContent).toBe(hostile);
    expect(container.querySelector("img")).toBeNull();
  });

  it("PID 0 sigue siendo un proceso válido", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 0, name: "System Idle" } })] });
    show({ showProcess: true });
    const row = await rowOf(1);
    expect(within(row).getByText("System Idle")).toHaveAttribute("title", "PID 0");
  });
});
