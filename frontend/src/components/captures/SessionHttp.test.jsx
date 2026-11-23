import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({ api: { sessionHttp: vi.fn(), httpBodyUrl: vi.fn((id, i) => `/api/sessions/${id}/http/${i}/body`) } }));
import { api } from "../../api/client.js";
import SessionHttp, { FileCard, httpNotes } from "./SessionHttp.jsx";

const session = { id: 4, protocol: "TCP" };
const file = (over = {}) => ({
  direction: "descarga", name: "setup.exe", size: 2048, sha256: "a".repeat(64), kind: "Ejecutable o librería de Windows (.exe/.dll)", risky: true,
  content_type: "application/octet-stream", complete: true, ...over,
});
const ex = (over = {}) => ({
  index: 0, method: "GET", target: "/a", host: "example.com", user_agent: "curl/8", auth: null, sensitive_fields: [], request_bytes: 0, request_type: null,
  status: 200, reason: "OK", response_type: "text/html", response_bytes: 1024, location: null, server: null, encoding: null, complete: true, file: null, ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.sessionHttp.mockResolvedValue({ exchanges: [ex()], incomplete: false });
});
const show = (props = {}) => render(<SessionHttp session={session} onError={onError} {...props} />);

describe("httpNotes", () => {
  it("sin nada raro: sin notas", () => expect(httpNotes(ex())).toEqual([]));
  it("campos de contraseña", () => {
    expect(httpNotes(ex({ sensitive_fields: ["password", "token"] }))).toEqual(["Envía un campo de contraseña SIN cifrar: password, token"]);
  });
  it("autenticación con y sin usuario", () => {
    expect(httpNotes(ex({ auth: { scheme: "Basic", user: "ana" } }))).toEqual(["Autenticación Basic (usuario ana) sin cifrar"]);
    expect(httpNotes(ex({ auth: { scheme: "Bearer" } }))).toEqual(["Autenticación Bearer sin cifrar"]);
    expect(httpNotes(ex({ auth: {} }))).toEqual([]);
    expect(httpNotes(ex({ auth: null }))).toEqual([]);
  });
  it("redirección e incompleto", () => {
    expect(httpNotes(ex({ location: "/home" }))).toEqual(["Redirige a /home"]);
    expect(httpNotes(ex({ complete: false }))).toEqual(["Incompleto: faltan bytes en la captura"]);
    expect(httpNotes(ex({ complete: undefined }))).toEqual([]);
  });
  it("todas juntas y en orden", () => {
    const n = httpNotes(ex({ sensitive_fields: ["pwd"], auth: { scheme: "Basic", user: "u" }, location: "/x", complete: false }));
    expect(n).toHaveLength(4);
    expect(n[0]).toContain("contraseña") && expect(n[3]).toContain("Incompleto");
  });
  it("campos ausentes no rompen", () => {
    expect(httpNotes({})).toEqual([]);
  });
  it("nunca incluye valores: solo lo que se le da", () => {
    expect(JSON.stringify(httpNotes(ex({ sensitive_fields: ["password"], auth: { scheme: "Basic", user: "ana" } })))).not.toContain("hunter2");
  });
});

describe("FileCard", () => {
  const draw = (f = file(), href = "/dl") => render(<ul><FileCard file={f} href={href} /></ul>);

  it("nombre, dirección, tamaño, tipo real, servidor y SHA-256", () => {
    const { container } = draw();
    expect(container.querySelector("strong")).toHaveTextContent("setup.exe");
    expect(container.textContent).toContain("descarga · 2.00 KB");
    expect(container.textContent).toContain("Tipo real: Ejecutable o librería de Windows (.exe/.dll) (el servidor dijo: application/octet-stream)");
    expect(container.textContent).toContain(`SHA-256: ${"a".repeat(64)}`);
  });

  it("riesgoso: clase 'file risky' y badge peligroso; no riesgoso: sin ellos", () => {
    const risky = draw(file({ risky: true }));
    expect(risky.container.querySelector("li").className).toBe("file risky");
    expect(screen.getByText("peligroso")).toBeInTheDocument();
    risky.unmount();
    const safe = draw(file({ risky: false, name: "a.pdf" }));
    expect(safe.container.querySelector("li").className).toBe("file");
    expect(screen.queryByText("peligroso")).toBeNull();
  });

  it("incompleto muestra su badge", () => {
    draw(file({ complete: false }));
    expect(screen.getByText("incompleto")).toBeInTheDocument();
  });

  it("completo no muestra badge de incompleto", () => {
    draw();
    expect(screen.queryByText("incompleto")).toBeNull();
  });

  it("sin content_type no menciona al servidor", () => {
    const { container } = draw(file({ content_type: "" }));
    expect(container.textContent).not.toContain("el servidor dijo");
  });

  it("el enlace baja como .bin con el atributo download", () => {
    draw(file(), "/api/sessions/4/http/0/body");
    const a = screen.getByRole("link", { name: "Guardar como .bin" });
    expect(a).toHaveAttribute("href", "/api/sessions/4/http/0/body");
    expect(a).toHaveAttribute("download");
  });

  describe("confirmación antes de descargar", () => {
    let confirm;
    afterEach(() => confirm?.mockRestore());

    it("si el usuario acepta, no se cancela el clic", async () => {
      confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
      draw();
      const a = screen.getByRole("link", { name: "Guardar como .bin" });
      const evt = new MouseEvent("click", { bubbles: true, cancelable: true });
      a.dispatchEvent(evt);
      expect(confirm).toHaveBeenCalledTimes(1);
      expect(evt.defaultPrevented).toBe(false);
    });

    it("si rechaza, se cancela (preventDefault) y no se baja nada", () => {
      confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
      draw();
      const evt = new MouseEvent("click", { bubbles: true, cancelable: true });
      screen.getByRole("link", { name: "Guardar como .bin" }).dispatchEvent(evt);
      expect(evt.defaultPrevented).toBe(true);
    });

    it("el mensaje advierte del malware y pide no abrirlo", () => {
      confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
      draw();
      screen.getByRole("link", { name: "Guardar como .bin" }).dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      const text = confirm.mock.calls[0][0];
      expect(text).toMatch(/malware/);
      expect(text).toMatch(/\.bin/);
      expect(text).toMatch(/No lo abras/);
    });

    it("nada se pregunta hasta que se hace clic", () => {
      confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
      draw();
      expect(confirm).not.toHaveBeenCalled();
    });
  });

  it("nombre y tipo hostiles se muestran como texto", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const { container } = draw(file({ name: evil, kind: evil, content_type: evil }));
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("strong").textContent).toBe(evil);
  });
});

describe("SessionHttp", () => {
  it("no renderiza nada mientras carga, sin HTTP, ni para sesiones que no son TCP", async () => {
    api.sessionHttp.mockReturnValue(new Promise(() => {}));
    expect(show().container).toBeEmptyDOMElement();
  });

  it("sin intercambios no dibuja nada", async () => {
    api.sessionHttp.mockResolvedValue({ exchanges: [], incomplete: false });
    const { container } = show();
    await waitFor(() => expect(api.sessionHttp).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("una sesión UDP ni siquiera pide", async () => {
    const { container } = show({ session: { id: 1, protocol: "UDP" } });
    await new Promise((r) => setTimeout(r, 0));
    expect(api.sessionHttp).not.toHaveBeenCalled();
    expect(container).toBeEmptyDOMElement();
  });

  it("tabla con pedido, respuesta y notas", async () => {
    api.sessionHttp.mockResolvedValue({
      incomplete: false,
      exchanges: [ex({ sensitive_fields: ["password"], auth: { scheme: "Basic", user: "ana" } }), ex({ index: 1, method: "POST", target: "/b", status: null, reason: null, response_type: null, response_bytes: 0, host: null, user_agent: null })],
    });
    const { container } = show();
    await screen.findByRole("heading", { name: /^HTTP/ });
    const rows = container.querySelectorAll("tbody tr");
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("GET")).toBeInTheDocument();
    expect(rows[0].textContent).toContain("example.com/a");
    expect(rows[0].textContent).toContain("curl/8");
    expect(rows[0].textContent).toContain("200 OK");
    expect(rows[0].textContent).toContain("text/html · 1.00 KB");
    expect(within(rows[0]).getByText(/Envía un campo de contraseña SIN cifrar: password/)).toBeInTheDocument();
    expect(within(rows[0]).getByText("Autenticación Basic (usuario ana) sin cifrar")).toBeInTheDocument();
    expect(rows[1].textContent).toContain("POST");
    expect(rows[1].textContent).toContain("—"); // sin estado
    expect(within(screen.getAllByRole("columnheader")[0].closest("table")).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Pedido", "Respuesta", "Notas"]);
  });

  it("aviso de incompleto con role=note", async () => {
    api.sessionHttp.mockResolvedValue({ exchanges: [ex()], incomplete: true });
    show();
    expect(await screen.findByRole("note")).toHaveTextContent("Faltan bytes en la captura");
  });

  it("sin 'incomplete' no hay aviso", async () => {
    show();
    await screen.findByRole("heading", { name: /^HTTP/ });
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("archivos: una tarjeta por intercambio con archivo y enlace a httpBodyUrl", async () => {
    api.sessionHttp.mockResolvedValue({ incomplete: false, exchanges: [ex({ index: 0 }), ex({ index: 2, file: file() })] });
    const { container } = show();
    expect(await screen.findByRole("heading", { name: /^Archivos/ })).toBeInTheDocument();
    expect(container.querySelectorAll("ul.files > li")).toHaveLength(1);
    expect(api.httpBodyUrl).toHaveBeenCalledWith(4, 2);
    expect(screen.getByRole("link", { name: "Guardar como .bin" })).toHaveAttribute("href", "/api/sessions/4/http/2/body");
  });

  it("sin archivos no hay sección Archivos", async () => {
    show();
    await screen.findByRole("heading", { name: /^HTTP/ });
    expect(screen.queryByRole("heading", { name: /^Archivos/ })).toBeNull();
  });

  it("ayudas de HTTP y de Archivos", async () => {
    api.sessionHttp.mockResolvedValue({ incomplete: false, exchanges: [ex({ file: file() })] });
    show();
    await screen.findByRole("heading", { name: /^Archivos/ });
    expect(screen.getAllByRole("button", { name: /^Ayuda: / })).toHaveLength(2);
  });

  it("al cambiar de sesión se vacía y se pide la nueva", async () => {
    const { rerender, container } = show();
    await screen.findByRole("heading", { name: /^HTTP/ });
    api.sessionHttp.mockResolvedValue({ exchanges: [], incomplete: false });
    rerender(<SessionHttp session={{ id: 8, protocol: "TCP" }} onError={onError} />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
    expect(api.sessionHttp).toHaveBeenLastCalledWith(8, expect.any(AbortSignal));
    expect(api.sessionHttp.mock.calls[0][1].aborted).toBe(true);
  });

  it("errores: onError con el mensaje; AbortError no", async () => {
    api.sessionHttp.mockRejectedValue(new Error("http roto"));
    show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("http roto"));
  });

  it("AbortError no se reporta y al desmontar se aborta", async () => {
    api.sessionHttp.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    const { unmount } = show();
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
    const signal = api.sessionHttp.mock.calls[0][1];
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it("pedido, host y user-agent hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.sessionHttp.mockResolvedValue({ incomplete: false, exchanges: [ex({ target: evil, host: evil, user_agent: evil, response_type: evil, location: evil })] });
    const { container } = show();
    await screen.findByRole("heading", { name: /^HTTP/ });
    expect(container.querySelector("img")).toBeNull();
  });
});
