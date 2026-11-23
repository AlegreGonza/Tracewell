import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within, waitFor, act } from "@testing-library/react";
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
    filteredPcapUrl: vi.fn((f = {}) => `/api/pcap?${new URLSearchParams(f)}`), sessionPackets: vi.fn(), packet: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionDetail from "./SessionDetail.jsx";

const session = {
  id: 7, protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80, packets: 3, bytes: 4096,
};
const pk = (index) => ({ index, ts: 1700000000 + index, caplen: 40, origlen: 40, snaplen_limited: false });

// Mismo formato que core/pcap/hexdump.py: '00000010  00 29 31 5a ...  |.)1Z@...|'
function hexdump(bytes, width = 16) {
  const lines = [];
  for (let off = 0; off < bytes.length; off += width) {
    const chunk = bytes.slice(off, off + width);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(width * 3 - 1, " ");
    const txt = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex}  |${txt}|`);
  }
  return lines.join("\n");
}
const BYTES = Array.from({ length: 40 }, (_, i) => 65 + (i % 26)); // 'A'..: 40 bytes imprimibles
const DUMP = hexdump(BYTES);

const field = (label, value, start, end, hint = null) => ({ label, value, start, end, hint });
const LAYERS = [
  {
    name: "Ethernet", start: 0, end: 14, note: null,
    fields: [field("MAC de destino", "aa:bb:cc:dd:ee:ff", 0, 6), field("Tipo", "0x0800 (IPv4)", 12, 14, "Qué protocolo viene dentro")],
  },
  {
    name: "TCP", start: 14, end: 34, note: "Capa incompleta: el paquete está cortado",
    fields: [field("Ventana", "251", 20, 22, "Cuántos bytes más acepta"), field("Cruce de líneas", "x", 14, 18)],
  },
];

const detail = (index, over = {}) => ({
  ...pk(index), session_id: 7,
  endpoints: { protocol: "TCP", src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80 },
  hexdump: DUMP, layers: LAYERS, ...over,
});

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  api.sessionPackets.mockResolvedValue({ items: [pk(10), pk(11)], has_more: false });
  api.packet.mockImplementation(async (i) => detail(i));
});

const renderIt = (s = session) => render(<SessionDetail session={s} onClose={() => {}} onError={onError} />);
const dump = async () => await screen.findByLabelText("Volcado hexadecimal");
const hl = (pre) => Array.from(pre.querySelectorAll(".hex-hl"));
const fieldBtn = (label) => screen.getByRole("button", { name: new RegExp(label) });

describe("SessionDetail: Sitio", () => {
  it("muestra 'Sitio: <host>' cuando la sesión lo trae", async () => {
    renderIt({ ...session, host: "login.evil.com" });
    await dump();
    const p = screen.getByText("login.evil.com").closest("p");
    expect(p).toHaveTextContent("Sitio: login.evil.com");
    expect(screen.getByText("login.evil.com")).toHaveClass("mono");
  });

  it("sin host (ausente, null o vacío) no muestra la línea", async () => {
    for (const host of [undefined, null, ""]) {
      const { unmount } = renderIt({ ...session, host });
      await dump();
      expect(screen.queryByText(/Sitio:/)).toBeNull();
      unmount();
    }
  });

  it("el host nunca se interpreta como HTML", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    const { container } = renderIt({ ...session, host: evil });
    await dump();
    expect(screen.getByText(evil)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("SessionDetail: sin capas", () => {
  it("una respuesta sin `layers` (mock viejo) no muestra la sección Capas", async () => {
    api.packet.mockImplementation(async (i) => {
      const { layers, ...old } = detail(i);
      return old;
    });
    renderIt();
    const pre = await dump();
    expect(screen.queryByRole("heading", { name: /^Capas/ })).toBeNull();
    expect(pre.textContent).toBe(DUMP);
  });

  it("layers vacío o null tampoco", async () => {
    for (const layers of [[], null]) {
      api.packet.mockImplementation(async (i) => detail(i, { layers }));
      const { unmount } = renderIt();
      await dump();
      expect(screen.queryByRole("heading", { name: /^Capas/ })).toBeNull();
      unmount();
    }
  });
});

describe("SessionDetail: hexdump con resaltado", () => {
  it("el texto del volcado es idéntico y trae spans por byte en las dos columnas", async () => {
    renderIt();
    const pre = await dump();
    expect(pre.textContent).toBe(DUMP);
    expect(pre.querySelectorAll(".hex-bytes span")).toHaveLength(40);
    expect(pre.querySelectorAll(".hex-ascii span")).toHaveLength(40);
    expect(pre.querySelectorAll(".hex-off")).toHaveLength(3);
    expect(hl(pre)).toHaveLength(0);
  });

  it("el volcado con resaltado conserva el mismo textContent", async () => {
    renderIt();
    const pre = await dump();
    const before = pre.textContent;
    await userEvent.hover(fieldBtn("Ventana"));
    expect(hl(pre).length).toBeGreaterThan(0);
    expect(pre.textContent).toBe(before);
  });

  it("resalta exactamente los bytes del rango, en hex y en ASCII", async () => {
    renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("Ventana")); // bytes 20..22
    const hex = Array.from(pre.querySelectorAll(".hex-bytes .hex-hl")).map((s) => s.textContent);
    const asc = Array.from(pre.querySelectorAll(".hex-ascii .hex-hl")).map((s) => s.textContent);
    expect(hex).toEqual([BYTES[20], BYTES[21]].map((b) => b.toString(16)));
    expect(asc).toEqual([String.fromCharCode(BYTES[20]), String.fromCharCode(BYTES[21])]);
  });

  it("un rango que cruza dos líneas resalta bytes de ambas", async () => {
    renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("Cruce de líneas")); // 14..18: 2 en la línea 0 y 2 en la 1
    expect(pre.querySelectorAll(".hex-bytes .hex-hl")).toHaveLength(4);
    expect(pre.querySelectorAll(".hex-ascii .hex-hl")).toHaveLength(4);
  });

  it("el fin del rango es exclusivo y el inicio inclusivo", async () => {
    renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("MAC de destino")); // 0..6
    const marked = Array.from(pre.querySelectorAll(".hex-bytes span")).map((s) => s.classList.contains("hex-hl"));
    expect(marked.slice(0, 6).every(Boolean)).toBe(true);
    expect(marked.slice(6).some(Boolean)).toBe(false);
  });

  it("un rango fuera del paquete no resalta nada ni rompe", async () => {
    api.packet.mockImplementation(async (i) => detail(i, { layers: [{ name: "X", start: 100, end: 120, note: null, fields: [field("Lejos", "1", 100, 120)] }] }));
    renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("Lejos"));
    expect(hl(pre)).toHaveLength(0);
    expect(pre.textContent).toBe(DUMP);
  });

  it("un rango vacío (start == end) no resalta nada", async () => {
    api.packet.mockImplementation(async (i) => detail(i, { layers: [{ name: "X", start: 3, end: 3, note: null, fields: [field("Vacio", "-", 3, 3)] }] }));
    renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("Vacio"));
    expect(hl(pre)).toHaveLength(0);
  });

  it("líneas que no tienen el formato esperado se muestran tal cual", async () => {
    const odd = `${DUMP}\nlinea rara sin formato`;
    api.packet.mockImplementation(async (i) => detail(i, { hexdump: odd }));
    renderIt();
    const pre = await dump();
    expect(pre.textContent).toBe(odd);
    await userEvent.hover(fieldBtn("Ventana"));
    expect(pre.textContent).toBe(odd);
  });

  it("sin hexdump muestra '(sin datos)'", async () => {
    api.packet.mockImplementation(async (i) => detail(i, { hexdump: "" }));
    renderIt();
    expect((await dump()).textContent).toBe("(sin datos)");
  });

  it("la última línea corta (relleno) mantiene las columnas y el resaltado correcto", async () => {
    renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("Cruce de líneas"));
    // la línea 2 (bytes 32..39) tiene 8 bytes + relleno: no debe haber spans fantasma
    const last = pre.querySelectorAll(".hex-bytes")[2];
    expect(last.querySelectorAll("span")).toHaveLength(8);
  });

  it("los caracteres del ASCII con HTML se muestran como texto", async () => {
    const bytes = Array.from("<b>x</b><img src=x>").map((c) => c.charCodeAt(0));
    api.packet.mockImplementation(async (i) => detail(i, { hexdump: hexdump(bytes), layers: [{ name: "D", start: 0, end: 3, note: null, fields: [field("Todo", "v", 0, 3)] }] }));
    const { container } = renderIt();
    const pre = await dump();
    await userEvent.hover(fieldBtn("Todo"));
    expect(pre.textContent).toContain("|<b>x</b><img src|");
    expect(pre.textContent).toContain("|=x>|");
    expect(container.querySelector("pre img, pre b")).toBeNull();
  });
});

describe("SessionDetail: árbol de capas", () => {
  it("una sección Capas con <details open> por capa y su resumen 'NOMBRE · bytes a–b'", async () => {
    const { container } = renderIt();
    await dump();
    expect(screen.getByRole("heading", { name: /^Capas/ })).toBeInTheDocument();
    const details = container.querySelectorAll(".layers details");
    expect(details).toHaveLength(2);
    details.forEach((d) => expect(d).toHaveAttribute("open"));
    const sums = Array.from(container.querySelectorAll(".layers summary")).map((s) => s.textContent);
    expect(sums).toEqual(["Ethernet · bytes 0–14", "TCP · bytes 14–34"]);
  });

  it("cada campo es un button.field con etiqueta, valor y pista", async () => {
    const { container } = renderIt();
    await dump();
    const btns = container.querySelectorAll("button.field");
    expect(btns).toHaveLength(4);
    const tipo = fieldBtn("Tipo");
    expect(within(tipo).getByText("Tipo")).toBeInTheDocument();
    expect(within(tipo).getByText("0x0800 (IPv4)")).toBeInTheDocument();
    expect(within(tipo).getByText("Qué protocolo viene dentro")).toBeInTheDocument();
    expect(tipo).toHaveAttribute("type", "button");
    expect(tipo).toHaveAttribute("aria-pressed", "false");
  });

  it("un campo sin pista no muestra el elemento de pista", async () => {
    renderIt();
    await dump();
    expect(fieldBtn("MAC de destino").querySelector(".field-hint")).toBeNull();
  });

  it("la nota de la capa se muestra con role=note", async () => {
    renderIt();
    await dump();
    expect(screen.getByRole("note")).toHaveTextContent("Capa incompleta: el paquete está cortado");
  });

  it("una capa sin nota no agrega role=note", async () => {
    api.packet.mockImplementation(async (i) => detail(i, { layers: [LAYERS[0]] }));
    renderIt();
    await dump();
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("una capa sin campos (incompleta) se muestra con su nota", async () => {
    api.packet.mockImplementation(async (i) => detail(i, { layers: [{ name: "TCP", start: 34, end: 40, fields: [], note: "Capa incompleta" }] }));
    const { container } = renderIt();
    await dump();
    expect(screen.getByRole("note")).toHaveTextContent("Capa incompleta");
    expect(container.querySelectorAll("button.field")).toHaveLength(0);
    expect(container.querySelector(".layers summary")).toHaveTextContent("TCP · bytes 34–40");
  });

  it("un valor/pista hostil se muestra como texto, nunca como HTML", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.packet.mockImplementation(async (i) =>
      detail(i, { layers: [{ name: evil, start: 0, end: 4, note: evil, fields: [field(evil, evil, 0, 4, evil)] }] }));
    const { container } = renderIt();
    await dump();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector(".layers").textContent.split(evil).length - 1).toBeGreaterThanOrEqual(4);
    expect(fieldBtn("img").textContent).toContain(evil);
  });

  it("colapsar una capa con el teclado no rompe el resaltado", async () => {
    const { container } = renderIt();
    const pre = await dump();
    const first = container.querySelector(".layers summary");
    await userEvent.click(first);
    expect(pre.textContent).toBe(DUMP);
  });
});

describe("SessionDetail: interacción campo <-> bytes", () => {
  it("pasar el mouse resalta y al salir se limpia", async () => {
    renderIt();
    const pre = await dump();
    const b = fieldBtn("Ventana");
    await userEvent.hover(b);
    expect(hl(pre)).toHaveLength(4);
    await userEvent.unhover(b);
    expect(hl(pre)).toHaveLength(0);
  });

  it("el foco resalta y el blur limpia (teclado)", async () => {
    renderIt();
    const pre = await dump();
    const b = fieldBtn("Ventana");
    act(() => b.focus());
    await waitFor(() => expect(hl(pre)).toHaveLength(4));
    act(() => b.blur());
    await waitFor(() => expect(hl(pre)).toHaveLength(0));
  });

  it("navegar con Tab recorre los campos y mueve el resaltado", async () => {
    renderIt();
    const pre = await dump();

    act(() => fieldBtn("MAC de destino").focus());
    expect(hl(pre)).toHaveLength(12); // 6 bytes x 2 columnas
    await userEvent.tab();
    expect(fieldBtn("Tipo")).toHaveFocus();
    expect(hl(pre)).toHaveLength(4); // 2 bytes x 2
  });

  it("pasar el mouse por el resumen de una capa resalta toda su extensión", async () => {
    const { container } = renderIt();
    const pre = await dump();
    const sum = container.querySelectorAll(".layers summary")[0];
    await userEvent.hover(sum);
    expect(pre.querySelectorAll(".hex-bytes .hex-hl")).toHaveLength(14);
    await userEvent.unhover(sum);
    expect(hl(pre)).toHaveLength(0);
  });

  it("un clic fija el campo (aria-pressed) y el resaltado sobrevive a salir con el mouse", async () => {
    renderIt();
    const pre = await dump();
    const b = fieldBtn("Ventana");
    await userEvent.click(b);
    expect(b).toHaveAttribute("aria-pressed", "true");
    await userEvent.unhover(b);
    expect(hl(pre)).toHaveLength(4);
    act(() => b.blur());
    await waitFor(() => expect(hl(pre)).toHaveLength(4));
  });

  it("un segundo clic suelta el campo", async () => {
    renderIt();
    const pre = await dump();
    const b = fieldBtn("Ventana");
    await userEvent.click(b);
    await userEvent.click(b);
    expect(b).toHaveAttribute("aria-pressed", "false");
    await userEvent.unhover(b);
    expect(hl(pre)).toHaveLength(0);
  });

  it("fijar otro campo reemplaza al anterior (solo uno fijado)", async () => {
    renderIt();
    const pre = await dump();
    await userEvent.click(fieldBtn("Ventana"));
    await userEvent.click(fieldBtn("Tipo"));
    expect(fieldBtn("Ventana")).toHaveAttribute("aria-pressed", "false");
    expect(fieldBtn("Tipo")).toHaveAttribute("aria-pressed", "true");
    await userEvent.unhover(fieldBtn("Tipo"));
    expect(pre.querySelectorAll(".hex-bytes .hex-hl")).toHaveLength(2);
  });

  it("con un campo fijado, pasar el mouse por otro muestra el otro y al salir vuelve al fijado", async () => {
    renderIt();
    const pre = await dump();
    await userEvent.click(fieldBtn("Ventana")); // 2 bytes
    await userEvent.hover(fieldBtn("MAC de destino")); // 6 bytes
    expect(pre.querySelectorAll(".hex-bytes .hex-hl")).toHaveLength(6);
    await userEvent.unhover(fieldBtn("MAC de destino"));
    expect(pre.querySelectorAll(".hex-bytes .hex-hl")).toHaveLength(2);
  });

  it("dos campos con la misma etiqueta y distinto inicio se fijan por separado", async () => {
    api.packet.mockImplementation(async (i) =>
      detail(i, { layers: [{ name: "IPv4", start: 0, end: 20, note: null, fields: [field("IP", "a", 0, 4), field("IP", "b", 4, 8)] }] }));
    renderIt();
    await dump();
    const [a, b] = screen.getAllByRole("button", { name: /^IP/ });
    await userEvent.click(a);
    expect(a).toHaveAttribute("aria-pressed", "true");
    expect(b).toHaveAttribute("aria-pressed", "false");
  });

  it("al cambiar de paquete se descarta lo fijado", async () => {
    renderIt();
    await dump();
    await userEvent.click(fieldBtn("Ventana"));
    expect(fieldBtn("Ventana")).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(screen.getByRole("button", { name: /#11/ }));
    await screen.findByLabelText("Volcado hexadecimal");
    await waitFor(() => expect(fieldBtn("Ventana")).toHaveAttribute("aria-pressed", "false"));
    expect(hl(screen.getByLabelText("Volcado hexadecimal"))).toHaveLength(0);
  });

  it("las capas se piden por paquete (api.packet con el índice)", async () => {
    renderIt();
    await dump();
    expect(api.packet).toHaveBeenCalledWith(10, expect.any(AbortSignal));
  });
});
