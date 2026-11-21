import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: {
    hosts: vi.fn(() => Promise.resolve({ total: 0, items: [] })),
    graph: vi.fn(() => Promise.resolve({ nodes: [], edges: [], truncated: false })),
    dns: vi.fn(() => Promise.resolve({ summary: { names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0, dropped: 0 }, items: [] })),
    explain: vi.fn(() => Promise.resolve({ protocol: "TCP", outcome: null, summary: [], steps: [] })),
    sessionHttp: vi.fn(() => Promise.resolve({ exchanges: [], incomplete: false })),
    sessionTls: vi.fn(() => Promise.resolve({ tls: false })),
    httpOverview: vi.fn(() => Promise.resolve({ scanned: 0, capped: false, items: [] })),
    httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`),
    sessionPcapUrl: vi.fn((id) => `/api/sessions/${id}/pcap`),
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`), sessionPackets: vi.fn(), packet: vi.fn(), saveNote: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionDetail from "./SessionDetail.jsx";

const XSS = "<script>alert(1)</script><img src=x onerror=alert(2)>";
const session = {
  id: 7, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80, packets: 3, bytes: 4096,
};

let onError, onNoteSaved;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  onNoteSaved = vi.fn();
  api.sessionPackets.mockResolvedValue({ items: [], has_more: false });
  api.saveNote.mockImplementation(async (id, body) => ({ id, note: body.note.trim(), reviewed: body.reviewed }));
});

const renderIt = (s = session) =>
  render(<SessionDetail session={s} onClose={vi.fn()} onError={onError} onNoteSaved={onNoteSaved} />);
const box = () => screen.getByLabelText("Nota del analista");
const check = () => screen.getByRole("checkbox", { name: "Marcar como revisada" });
const save = () => screen.getByRole("button", { name: "Guardar nota" });

describe("SessionDetail: nota del analista", () => {
  it("sin anotaciones: campo vacío y casilla sin marcar", async () => {
    renderIt();
    expect(box()).toHaveValue("");
    expect(check()).not.toBeChecked();
    await screen.findByText("Sesión 7");
  });

  it("precarga nota y marca existentes", () => {
    renderIt({ ...session, note: "ya vista", reviewed: true });
    expect(box()).toHaveValue("ya vista");
    expect(check()).toBeChecked();
  });

  it("guardar llama api.saveNote(id, {note, reviewed}) y onNoteSaved con la sesión actualizada", async () => {
    renderIt();
    await userEvent.type(box(), "  sospechosa ");
    await userEvent.click(check());
    await userEvent.click(save());
    expect(api.saveNote).toHaveBeenCalledWith(7, { note: "  sospechosa ", reviewed: true });
    await vi.waitFor(() => expect(onNoteSaved).toHaveBeenCalledTimes(1));
    expect(onNoteSaved.mock.calls[0][0]).toEqual({ ...session, note: "sospechosa", reviewed: true });
    expect(await screen.findByRole("status")).toHaveTextContent("Guardada");
  });

  it("solo marcar revisada (sin texto) conserva reviewed y deja note indefinida", async () => {
    renderIt();
    await userEvent.click(check());
    await userEvent.click(save());
    await vi.waitFor(() => expect(onNoteSaved).toHaveBeenCalled());
    const updated = onNoteSaved.mock.calls[0][0];
    expect(updated.reviewed).toBe(true);
    expect(updated.note).toBeUndefined();
  });

  it("vaciar nota y desmarcar quita las claves note/reviewed de la sesión", async () => {
    renderIt({ ...session, note: "algo", reviewed: true });
    await userEvent.clear(box());
    await userEvent.click(check());
    await userEvent.click(save());
    await vi.waitFor(() => expect(onNoteSaved).toHaveBeenCalled());
    const updated = onNoteSaved.mock.calls[0][0];
    expect(updated).toEqual(session);
    expect("note" in updated).toBe(false);
    expect("reviewed" in updated).toBe(false);
  });

  it("una nota de solo espacios sin marca también quita las claves", async () => {
    renderIt();
    await userEvent.type(box(), "   ");
    await userEvent.click(save());
    await vi.waitFor(() => expect(onNoteSaved).toHaveBeenCalled());
    expect(onNoteSaved.mock.calls[0][0]).toEqual(session);
  });

  it("no pisa otras claves de la sesión (proceso, ioc)", async () => {
    const rich = { ...session, process: { pid: 1, name: "a.exe" }, ioc: ["ip:10.0.0.2"] };
    renderIt(rich);
    await userEvent.type(box(), "x");
    await userEvent.click(save());
    await vi.waitFor(() => expect(onNoteSaved).toHaveBeenCalled());
    expect(onNoteSaved.mock.calls[0][0]).toMatchObject({ process: rich.process, ioc: rich.ioc, note: "x" });
  });

  it("si el guardado falla: onError con el mensaje, sin onNoteSaved ni 'Guardada', y se puede reintentar", async () => {
    api.saveNote.mockRejectedValueOnce(Object.assign(new Error("demasiadas notas (máximo 5000)"), { status: 409 }));
    renderIt();
    await userEvent.type(box(), "x");
    await userEvent.click(save());
    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("demasiadas notas (máximo 5000)"));
    expect(onNoteSaved).not.toHaveBeenCalled();
    expect(screen.queryByText("Guardada")).toBeNull();
    expect(save()).toBeEnabled();
    expect(box()).toHaveValue("x"); // no se pierde lo escrito
    await userEvent.click(save());
    expect(await screen.findByText("Guardada")).toBeInTheDocument();
  });

  it("el botón se deshabilita mientras guarda", async () => {
    let resolve;
    api.saveNote.mockReturnValue(new Promise((r) => { resolve = r; }));
    renderIt();
    await userEvent.type(box(), "x");
    await userEvent.click(save());
    expect(save()).toBeDisabled();
    resolve({ id: 7, note: "x", reviewed: false });
    await screen.findByText("Guardada");
    expect(save()).toBeEnabled();
  });

  it("'Guardada' desaparece si se cambia de sesión", async () => {
    const { rerender } = renderIt();
    await userEvent.type(box(), "x");
    await userEvent.click(save());
    await screen.findByText("Guardada");
    rerender(<SessionDetail session={{ ...session, id: 8 }} onClose={vi.fn()} onError={onError} onNoteSaved={onNoteSaved} />);
    expect(screen.queryByText("Guardada")).toBeNull();
    expect(box()).toHaveValue("");
  });

  it("al cambiar de sesión recarga el borrador con la nota de la nueva", () => {
    const { rerender } = renderIt({ ...session, note: "A", reviewed: true });
    rerender(<SessionDetail session={{ ...session, id: 8, note: "B" }} onClose={vi.fn()} onError={onError} onNoteSaved={onNoteSaved} />);
    expect(box()).toHaveValue("B");
    expect(check()).not.toBeChecked();
  });

  it("el textarea limita a 2000 caracteres", () => {
    renderIt();
    expect(box()).toHaveAttribute("maxlength", "2000");
  });

  it("funciona sin onNoteSaved (prop opcional)", async () => {
    render(<SessionDetail session={session} onClose={vi.fn()} onError={onError} />);
    await userEvent.type(box(), "x");
    await userEvent.click(save());
    expect(await screen.findByText("Guardada")).toBeInTheDocument();
  });

  it("texto hostil en la nota se muestra como texto en el campo, nunca como HTML", async () => {
    const { container } = renderIt({ ...session, note: XSS });
    expect(box()).toHaveValue(XSS);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("escribir texto hostil, guardarlo y reflejarlo no inyecta nodos", async () => {
    const { container } = renderIt();
    await userEvent.type(box(), "<img src=x onerror=alert(1)>", { skipClick: false });
    await userEvent.click(save());
    await screen.findByText("Guardada");
    expect(api.saveNote.mock.calls[0][1].note).toBe("<img src=x onerror=alert(1)>");
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("SessionDetail: coincidencia con IOC", () => {
  it("muestra el aviso con los indicadores como texto", async () => {
    renderIt({ ...session, ioc: ["ip:10.0.0.2", "dominio:evil.com"] });
    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("Coincide con un indicador de compromiso");
    expect(note).toHaveTextContent("ip:10.0.0.2, dominio:evil.com");
    await screen.findByText("Sesión 7");
  });

  it("sin ioc o con lista vacía no hay aviso", async () => {
    const { rerender } = renderIt();
    expect(screen.queryByText(/indicador de compromiso/)).toBeNull();
    rerender(<SessionDetail session={{ ...session, ioc: [] }} onClose={vi.fn()} onError={onError} />);
    expect(screen.queryByText(/indicador de compromiso/)).toBeNull();
    await screen.findByText("Sesión 7");
  });

  it("indicadores con marcado HTML no inyectan nodos", async () => {
    const { container } = renderIt({ ...session, ioc: ["dominio:<img src=x>"] });
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByRole("note")).toHaveTextContent("<img src=x>");
    await screen.findByText("Sesión 7");
  });
});
