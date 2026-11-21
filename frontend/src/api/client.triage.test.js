import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api, ApiError } from "./client.js";

const ok = (body) => ({ ok: true, status: 200, statusText: "OK", json: async () => body });
const fail = (status, body) => ({ ok: false, status, statusText: "Err", json: async () => body });

let fetchMock;
beforeEach(() => {
  fetchMock = vi.fn().mockResolvedValue(ok({}));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());
const last = () => fetchMock.mock.calls.at(-1);

describe("api: triaje", () => {
  it("saveNote: PUT /api/sessions/{id}/note con el cuerpo", async () => {
    await api.saveNote(7, { note: "hola", reviewed: true });
    const [url, opts] = last();
    expect(url).toBe("/api/sessions/7/note");
    expect(opts.method).toBe("PUT");
    expect(JSON.parse(opts.body)).toEqual({ note: "hola", reviewed: true });
    expect(opts.headers).toEqual({ "Content-Type": "application/json" });
  });

  it("saveNote codifica el id en la URL", async () => {
    await api.saveNote("a/b?c", { note: "", reviewed: false });
    expect(last()[0]).toBe("/api/sessions/a%2Fb%3Fc/note");
  });

  it("saveNote con texto hostil lo manda como JSON, sin tocar la URL", async () => {
    await api.saveNote(1, { note: '"><script>alert(1)</script>', reviewed: false });
    expect(last()[0]).toBe("/api/sessions/1/note");
    expect(JSON.parse(last()[1].body).note).toBe('"><script>alert(1)</script>');
  });

  it("iocs: GET /api/iocs con la señal de aborto", async () => {
    const ctl = new AbortController();
    await api.iocs(ctl.signal);
    const [url, opts] = last();
    expect(url).toBe("/api/iocs");
    expect(opts.method).toBe("GET");
    expect(opts.signal).toBe(ctl.signal);
  });

  it("loadIocs: POST /api/iocs con {path}", async () => {
    await api.loadIocs("C:\\listas\\feed.txt");
    const [url, opts] = last();
    expect(url).toBe("/api/iocs");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ path: "C:\\listas\\feed.txt" });
  });

  it("clearIocs: DELETE /api/iocs sin cuerpo", async () => {
    await api.clearIocs();
    const [url, opts] = last();
    expect(url).toBe("/api/iocs");
    expect(opts.method).toBe("DELETE");
    expect(opts.body).toBeUndefined();
  });

  it("reportUrl devuelve la URL de descarga", () => {
    expect(api.reportUrl()).toBe("/api/report");
  });

  it("loadIocs: un 422 se traduce a ApiError con el detalle del servidor", async () => {
    fetchMock.mockResolvedValue(fail(422, { detail: "línea 3: no es una IP, una red ni un dominio" }));
    await expect(api.loadIocs("x")).rejects.toMatchObject({ status: 422, detail: "línea 3: no es una IP, una red ni un dominio" });
    await expect(api.loadIocs("x")).rejects.toBeInstanceOf(ApiError);
  });

  it("saveNote: un 409 conserva el mensaje", async () => {
    fetchMock.mockResolvedValue(fail(409, { detail: "no hay una captura analizada" }));
    await expect(api.saveNote(1, { note: "x", reviewed: false })).rejects.toMatchObject({ status: 409 });
  });

  it("saveNote: error de validación (lista) se normaliza a texto", async () => {
    fetchMock.mockResolvedValue(fail(422, { detail: [{ loc: ["body", "note"], msg: "demasiado largo" }] }));
    await expect(api.saveNote(1, { note: "x", reviewed: false })).rejects.toMatchObject({ detail: "note: demasiado largo" });
  });

  it("sin red: ApiError con status 0", async () => {
    fetchMock.mockRejectedValue(new TypeError("fetch failed"));
    await expect(api.clearIocs()).rejects.toMatchObject({ status: 0 });
  });
});
