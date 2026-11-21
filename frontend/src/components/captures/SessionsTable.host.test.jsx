import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

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

describe("SessionsTable columna Sitio", () => {
  it("sin ningún host no hay columna", async () => {
    api.sessions.mockResolvedValue({ total: 2, items: [sess(1), sess(2)] });
    show();
    const row = await rowOf(1);
    expect(screen.queryByRole("columnheader", { name: "Sitio" })).toBeNull();
    expect(within(row).getAllByRole("cell")).toHaveLength(7);
  });

  it("con algún host aparece la columna: el nombre donde hay y '—' en el resto", async () => {
    api.sessions.mockResolvedValue({ total: 2, items: [sess(1, { host: "login.evil.com" }), sess(2)] });
    show();
    const r1 = await rowOf(1);
    const r2 = await rowOf(2);
    expect(screen.getByRole("columnheader", { name: "Sitio" })).toBeInTheDocument();
    expect(within(r1).getByText("login.evil.com")).toHaveClass("mono");
    expect(within(r1).getAllByRole("cell")).toHaveLength(8);
    expect(within(r2).getByText("—")).toBeInTheDocument();
    expect(within(r2).getAllByRole("cell")).toHaveLength(8);
  });

  it("la columna Sitio va entre Destino y Paquetes", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { host: "a.test" })] });
    show();
    await rowOf(1);
    const heads = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads).toEqual(["#", "Protocolo", "Origen", "Destino", "Sitio", "Paquetes", "Bytes", "Duración"]);
  });

  it("con showProcess también: Sitio antes de Proceso", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { host: "a.test", process: { pid: 1, name: "p.exe" } })] });
    show({ showProcess: true });
    await rowOf(1);
    const heads = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads.indexOf("Sitio")).toBe(heads.indexOf("Proceso") - 1);
  });

  it("host vacío o null no cuenta como conocido", async () => {
    api.sessions.mockResolvedValue({ total: 2, items: [sess(1, { host: "" }), sess(2, { host: null })] });
    show();
    await rowOf(1);
    expect(screen.queryByRole("columnheader", { name: "Sitio" })).toBeNull();
  });

  it("el host se muestra solo como texto, nunca como HTML", async () => {
    const evil = "<img src=x onerror=alert(1)>.test";
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { host: evil })] });
    const { container } = show();
    const row = await rowOf(1);
    expect(within(row).getByText(evil)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("la columna depende de la página: desaparece si la página nueva no trae hosts", async () => {
    api.sessions
      .mockResolvedValueOnce({ total: 30, items: [sess(1, { host: "a.test" })] })
      .mockResolvedValueOnce({ total: 30, items: [sess(26)] });
    show();
    await rowOf(1);
    expect(screen.getByRole("columnheader", { name: "Sitio" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Siguiente" }));
    await rowOf(26);
    await waitFor(() => expect(screen.queryByRole("columnheader", { name: "Sitio" })).toBeNull());
  });
});
