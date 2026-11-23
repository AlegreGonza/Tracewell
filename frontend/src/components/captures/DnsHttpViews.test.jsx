import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { dns: vi.fn(), httpOverview: vi.fn() } }));
import { api } from "../../api/client.js";
import DnsView from "./DnsView.jsx";
import HttpView from "./HttpView.jsx";

const row = (over = {}) => ({
  name: "example.com", qtype: "A", queries: 2, responses: 1, rcodes: { NOERROR: 1 }, answers: ["1.2.3.4"], clients: ["10.0.0.5"],
  first_ts: 1700000000, last_ts: 1700000005, min_ttl: 300, hints: [], ...over,
});
const summary = (over = {}) => ({ names: 2, queries: 4, responses: 3, nxdomain: 1, flagged: 1, dropped: 0, ...over });
const dnsData = (items = [row()], s = summary()) => ({ summary: s, items });

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.dns.mockResolvedValue(dnsData());
  api.httpOverview.mockResolvedValue({ scanned: 1, capped: false, items: [] });
});

// =========================================================================== DnsView
describe("DnsView", () => {
  const show = (props = {}) => render(<DnsView refreshKey={0} onError={onError} {...props} />);

  it("no dibuja nada mientras carga", () => {
    api.dns.mockReturnValue(new Promise(() => {}));
    expect(show().container).toBeEmptyDOMElement();
  });

  it("no dibuja nada si la captura no tiene DNS (0 nombres y sin filtro)", async () => {
    api.dns.mockResolvedValue(dnsData([], summary({ names: 0, queries: 0, responses: 0, nxdomain: 0, flagged: 0 })));
    const { container } = show();
    await waitFor(() => expect(api.dns).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("resumen en la cabecera y ayuda", async () => {
    show();
    expect(await screen.findByRole("heading", { name: "DNS" })).toBeInTheDocument();
    expect(screen.getByText("2 nombres · 4 consultas · 1 NXDOMAIN · 1 con pistas")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
  });

  it("los números grandes se formatean", async () => {
    api.dns.mockResolvedValue(dnsData([row()], summary({ names: 1234, queries: 56789 })));
    show();
    expect(await screen.findByText(/1\.234 nombres · 56\.789 consultas/)).toBeInTheDocument();
  });

  it("la tabla está dentro de un <details> cerrado que se abre y se cierra", async () => {
    const { container } = show();
    await screen.findByRole("heading", { name: "DNS" });
    const d = container.querySelector("details.dns-details");
    expect(d.open).toBe(false);
    await userEvent.click(screen.getByText("Ver la tabla de DNS"));
    expect(d.open).toBe(true);
    await userEvent.click(screen.getByText("Ver la tabla de DNS"));
    expect(d.open).toBe(false);
  });

  it("columnas y fila: nombre, tipo, consultas, respuestas, resultado, respondió, TTL", async () => {
    const { container } = show();
    await screen.findByRole("heading", { name: "DNS" });
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(
      ["Nombre", "Tipo", "Consultas", "Respuestas", "Resultado", "Respondió", "TTL mín.", "Pistas"]);
    const cells = Array.from(container.querySelectorAll("tbody tr td")).map((c) => c.textContent);
    expect(cells).toEqual(["example.com", "A", "2", "1", "NOERROR×1", "1.2.3.4", "300", ""]);
    expect(container.querySelector("tbody tr")).toHaveAttribute("title", expect.stringMatching(/^Visto de 22:13:20\.000 UTC a 22:13:25\.000 UTC$/));
  });

  it("valores vacíos se muestran como '—'", async () => {
    api.dns.mockResolvedValue(dnsData([row({ rcodes: {}, answers: [], min_ttl: null })]));
    const { container } = show();
    await screen.findByRole("heading", { name: "DNS" });
    const cells = Array.from(container.querySelectorAll("tbody tr td")).map((c) => c.textContent);
    expect(cells.slice(4, 7)).toEqual(["—", "—", "—"]);
  });

  it("varios códigos de resultado y varias respuestas", async () => {
    api.dns.mockResolvedValue(dnsData([row({ rcodes: { NXDOMAIN: 2, NOERROR: 1 }, answers: ["1.1.1.1", "2.2.2.2"] })]));
    const { container } = show();
    await screen.findByRole("heading", { name: "DNS" });
    const cells = Array.from(container.querySelectorAll("tbody tr td")).map((c) => c.textContent);
    expect(cells[4]).toBe("NXDOMAIN×2 NOERROR×1");
    expect(cells[5]).toBe("1.1.1.1, 2.2.2.2");
  });

  it("las pistas se muestran como notas", async () => {
    api.dns.mockResolvedValue(dnsData([row({ hints: ["El nombre no existe (NXDOMAIN).", "TTL muy bajo."] })]));
    const { container } = show();
    await screen.findByRole("heading", { name: "DNS" });
    expect(Array.from(container.querySelectorAll(".note-chip")).map((c) => c.textContent)).toEqual(["El nombre no existe (NXDOMAIN).", "TTL muy bajo."]);
  });

  it("nombres y respuestas hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.dns.mockResolvedValue(dnsData([row({ name: evil, answers: [evil], hints: [evil], rcodes: { [evil]: 1 } })]));
    const { container } = show();
    await screen.findByRole("heading", { name: "DNS" });
    expect(container.querySelector("img")).toBeNull();
  });

  it("la primera petición es sin filtro; buscar aplica al enviar, no al tipear", async () => {
    show();
    await screen.findByRole("heading", { name: "DNS" });
    expect(api.dns).toHaveBeenLastCalledWith(undefined, expect.any(AbortSignal));
    await userEvent.type(screen.getByLabelText("Buscar un nombre"), "goo");
    expect(api.dns).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
    await waitFor(() => expect(api.dns).toHaveBeenCalledTimes(2));
    expect(api.dns).toHaveBeenLastCalledWith("goo", expect.any(AbortSignal));
  });

  it("Enter envía la búsqueda y se recortan los espacios", async () => {
    show();
    await screen.findByRole("heading", { name: "DNS" });
    await userEvent.type(screen.getByLabelText("Buscar un nombre"), "  evil  {Enter}");
    await waitFor(() => expect(api.dns).toHaveBeenLastCalledWith("evil", expect.any(AbortSignal)));
  });

  it("buscar vacío quita el filtro (vuelve a pedir sin q)", async () => {
    show();
    await screen.findByRole("heading", { name: "DNS" });
    await userEvent.type(screen.getByLabelText("Buscar un nombre"), "a{Enter}");
    await waitFor(() => expect(api.dns).toHaveBeenLastCalledWith("a", expect.any(AbortSignal)));
    await userEvent.clear(screen.getByLabelText("Buscar un nombre"));
    await userEvent.click(screen.getByRole("button", { name: "Buscar" }));
    await waitFor(() => expect(api.dns).toHaveBeenLastCalledWith(undefined, expect.any(AbortSignal)));
  });

  it("una búsqueda sin resultados mantiene la sección y muestra el mensaje", async () => {
    show();
    await screen.findByRole("heading", { name: "DNS" });
    api.dns.mockResolvedValue(dnsData([], summary()));
    await userEvent.type(screen.getByLabelText("Buscar un nombre"), "zzz{Enter}");
    expect(await screen.findByText("Ningún nombre coincide.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS" })).toBeInTheDocument();
  });

  it("vuelve a pedir si cambia refreshKey", async () => {
    const { rerender } = show();
    await screen.findByRole("heading", { name: "DNS" });
    rerender(<DnsView refreshKey={1} onError={onError} />);
    await waitFor(() => expect(api.dns).toHaveBeenCalledTimes(2));
    expect(api.dns.mock.calls[0][1].aborted).toBe(true);
  });

  it("error -> onError; AbortError no; al desmontar se aborta", async () => {
    api.dns.mockRejectedValue(new Error("dns roto"));
    const { container, unmount } = show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("dns roto"));
    expect(container).toBeEmptyDOMElement();
    unmount();
    api.dns.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    const again = show();
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).toHaveBeenCalledTimes(1);
    const signal = api.dns.mock.calls.at(-1)[1];
    again.unmount();
    expect(signal.aborted).toBe(true);
  });
});

// =========================================================================== HttpView
const ex = (over = {}) => ({
  index: 0, session_id: 3, src: "192.168.1.10:51000", dst: "93.184.216.34:80", method: "GET", target: "/index.html", host: "www.example.com",
  status: 200, response_type: "text/html", response_bytes: 2048, sensitive_fields: [], auth: null, location: null, complete: true, file: null, ...over,
});
const fileOf = (over = {}) => ({ name: "setup.exe", kind: "Ejecutable de Windows", risky: true, sha256: "ab".repeat(32), size: 10, direction: "descarga", complete: true, ...over });

describe("HttpView", () => {
  let onFilterIp;
  beforeEach(() => {
    onFilterIp = vi.fn();
  });
  const show = (items, extra = {}, props = {}) => {
    api.httpOverview.mockResolvedValue({ scanned: 1, capped: false, items, ...extra });
    return render(<HttpView refreshKey={0} onError={onError} onFilterIp={onFilterIp} {...props} />);
  };

  it("no dibuja nada mientras carga ni si no hay peticiones", async () => {
    api.httpOverview.mockReturnValue(new Promise(() => {}));
    expect(render(<HttpView refreshKey={0} onError={onError} />).container).toBeEmptyDOMElement();
  });

  it("sin items no dibuja nada", async () => {
    const { container } = show([]);
    await waitFor(() => expect(api.httpOverview).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("cabecera con peticiones, archivos y credenciales", async () => {
    show([
      ex(),
      ex({ index: 1, file: fileOf() }),
      ex({ index: 2, sensitive_fields: ["password"] }),
      ex({ index: 3, auth: { scheme: "Basic", user: "ana" } }),
    ]);
    expect(await screen.findByRole("heading", { name: "HTTP sin cifrar" })).toBeInTheDocument();
    expect(screen.getByText("4 petición(es) · 1 archivo(s) · 2 con credenciales")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ayuda: / })).toBeInTheDocument();
  });

  it("solo contraseñas y autenticación cuentan como credenciales (redirección o incompleto no)", async () => {
    show([ex({ location: "/x" }), ex({ index: 1, complete: false })]);
    expect(await screen.findByText("2 petición(es) · 0 archivo(s) · 0 con credenciales")).toBeInTheDocument();
  });

  it("fila: sesión, origen, pedido, estado, tipo, tamaño", async () => {
    const { container } = show([ex()]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    const cells = Array.from(container.querySelectorAll("tbody tr td")).map((c) => c.textContent);
    expect(cells[0]).toBe("#3 192.168.1.10:51000");
    expect(cells[1]).toBe("GET www.example.com/index.html");
    expect(cells.slice(2, 5)).toEqual(["200", "text/html", "2.00 KB"]);
  });

  it("sin host usa el destino; sin estado ni tipo muestra '—'", async () => {
    const { container } = show([ex({ host: null, status: null, response_type: null, response_bytes: 0 })]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    const cells = Array.from(container.querySelectorAll("tbody tr td")).map((c) => c.textContent);
    expect(cells[1]).toBe("GET 93.184.216.34:80/index.html");
    expect(cells[2]).toBe("—");
    expect(cells[3]).toBe("—");
  });

  it("clic en la IP de origen llama a onFilterIp con la IP sola (sin puerto)", async () => {
    show([ex()]);
    await userEvent.click(await screen.findByRole("button", { name: "192.168.1.10:51000" }));
    expect(onFilterIp).toHaveBeenCalledTimes(1);
    expect(onFilterIp).toHaveBeenCalledWith("192.168.1.10");
  });

  it("origen IPv6: se corta en el primer ':' (comportamiento actual)", async () => {
    show([ex({ src: "10.0.0.1:1" })]);
    await userEvent.click(await screen.findByRole("button", { name: "10.0.0.1:1" }));
    expect(onFilterIp).toHaveBeenCalledWith("10.0.0.1");
  });

  it("usa src_ip tal cual: una IPv6 se pasa entera (sin cortar en ':')", async () => {
    show([ex({ src: "fe80::1:51000", src_ip: "fe80::1", dst: "fe80::2:80", dst_ip: "fe80::2" })]);
    await userEvent.click(await screen.findByRole("button", { name: "fe80::1:51000" }));
    expect(onFilterIp).toHaveBeenCalledTimes(1);
    expect(onFilterIp).toHaveBeenCalledWith("fe80::1");
  });

  it("IPv6 global con src_ip", async () => {
    show([ex({ src: "2001:db8::1:51000", src_ip: "2001:db8::1" })]);
    await userEvent.click(await screen.findByRole("button", { name: "2001:db8::1:51000" }));
    expect(onFilterIp).toHaveBeenCalledWith("2001:db8::1");
  });

  it("sin src_ip (respuesta vieja) corta en el ÚLTIMO ':' también para IPv6", async () => {
    show([ex({ src: "fe80::1:51000", src_ip: undefined })]);
    await userEvent.click(await screen.findByRole("button", { name: "fe80::1:51000" }));
    expect(onFilterIp).toHaveBeenCalledWith("fe80::1");
  });

  it("sin src_ip y con IPv4 sigue dando la IP sola", async () => {
    show([ex({ src_ip: undefined })]);
    await userEvent.click(await screen.findByRole("button", { name: "192.168.1.10:51000" }));
    expect(onFilterIp).toHaveBeenCalledWith("192.168.1.10");
  });

  it("src_ip tiene prioridad sobre src aunque no coincidan", async () => {
    show([ex({ src: "1.1.1.1:5", src_ip: "9.9.9.9" })]);
    await userEvent.click(await screen.findByRole("button", { name: "1.1.1.1:5" }));
    expect(onFilterIp).toHaveBeenCalledWith("9.9.9.9");
  });

  it("sin onFilterIp el clic no rompe", async () => {
    show([ex()], {}, { onFilterIp: undefined });
    await userEvent.click(await screen.findByRole("button", { name: "192.168.1.10:51000" }));
  });

  it("chip del archivo con nombre, tipo y SHA-256 recortado; riesgoso agrega la clase", async () => {
    const { container } = show([ex({ file: fileOf() }), ex({ index: 1, file: fileOf({ risky: false, name: "a.pdf", kind: "PDF" }) })]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    const chips = container.querySelectorAll(".note-chip");
    expect(chips[0].textContent).toBe(`Archivo setup.exe: Ejecutable de Windows · SHA-256 ${"ab".repeat(8)}…`);
    expect(chips[0].className).toBe("note-chip risky");
    expect(chips[1].className).toBe("note-chip");
  });

  it("notas: contraseñas, autenticación, redirección e incompleto", async () => {
    const { container } = show([ex({ sensitive_fields: ["password"], auth: { scheme: "Basic", user: "ana" }, location: "/home", complete: false })]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    const notes = Array.from(container.querySelectorAll(".note-chip")).map((n) => n.textContent);
    expect(notes).toHaveLength(4);
  });

  it("capped muestra el aviso con role=note; sin capped no", async () => {
    const a = show([ex()], { capped: true });
    expect(await screen.findByRole("note")).toHaveTextContent("Se muestran solo las primeras");
    a.unmount();
    show([ex()], { capped: false });
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("columnas de la tabla", async () => {
    show([ex()]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Sesión", "Pedido", "Estado", "Tipo", "Tamaño", "Notas"]);
  });

  it("textos hostiles se muestran como texto", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    const { container } = show([ex({ target: evil, host: evil, response_type: evil, file: fileOf({ name: evil, kind: evil }) })]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    expect(container.querySelector("img")).toBeNull();
  });

  it("refreshKey vuelve a pedir; error -> onError; AbortError no; desmontar aborta", async () => {
    api.httpOverview.mockResolvedValue({ scanned: 1, capped: false, items: [ex()] });
    const { rerender, unmount } = render(<HttpView refreshKey={0} onError={onError} />);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    rerender(<HttpView refreshKey={1} onError={onError} />);
    await waitFor(() => expect(api.httpOverview).toHaveBeenCalledTimes(2));
    expect(api.httpOverview.mock.calls[0][0].aborted).toBe(true);
    const signal = api.httpOverview.mock.calls[1][0];
    unmount();
    expect(signal.aborted).toBe(true);
    api.httpOverview.mockRejectedValue(new Error("scan roto"));
    render(<HttpView refreshKey={0} onError={onError} />);
    await waitFor(() => expect(onError).toHaveBeenCalledWith("scan roto"));
    api.httpOverview.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    render(<HttpView refreshKey={2} onError={onError} />);
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("varias filas conservan el orden", async () => {
    const { container } = show([ex({ index: 0, target: "/a" }), ex({ index: 1, target: "/b", session_id: 9 })]);
    await screen.findByRole("heading", { name: "HTTP sin cifrar" });
    const rows = container.querySelectorAll("tbody tr");
    expect(within(rows[0]).getByText(/\/a/)).toBeInTheDocument();
    expect(rows[1].textContent).toContain("#9");
  });
});
