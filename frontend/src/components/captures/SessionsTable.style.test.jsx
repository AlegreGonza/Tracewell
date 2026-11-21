import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";

vi.mock("../../api/client.js", () => ({ api: { sessions: vi.fn() } }));
import { api } from "../../api/client.js";
import SessionsTable, { processColor, protoClass } from "./SessionsTable.jsx";

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
const dotOf = (row) => row.querySelector(".dot");
const procN = (row) => Number(/proc-(\d+)/.exec(dotOf(row).className)[1]);

beforeEach(() => vi.clearAllMocks());

describe("protoClass", () => {
  it.each([
    ["TCP", "tcp"], ["UDP", "udp"], ["ICMP", "icmp"], ["ICMPv6", "icmpv6"],
    ["tcp", "tcp"], ["Udp", "udp"], ["icmpV6", "icmpv6"],
  ])("%s -> %s", (p, c) => expect(protoClass(p)).toBe(c));

  it.each([["IP-2"], ["IP-47"], [""], [null], [undefined], [" tcp"], ["tcp "], ["SCTP"], ["TCP6"], [6], [{}]])(
    "%j -> other", (p) => expect(protoClass(p)).toBe("other"),
  );
});

describe("processColor", () => {
  it("el mismo nombre siempre da el mismo número", () => {
    const a = processColor("same-name-A");
    expect(processColor("same-name-A")).toBe(a);
    expect(processColor("same-name-A")).toBe(a);
  });

  it("devuelve un entero de 1 a 8, para cualquier nombre", () => {
    for (const n of ["x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "ñandú.exe", "<b>", "0", " "]) {
      const c = processColor(n);
      expect(Number.isInteger(c) && c >= 1 && c <= 8).toBe(true);
    }
  });

  it("null, undefined y '' son el mismo nombre", () => {
    const e = processColor("");
    expect(processColor(null)).toBe(e);
    expect(processColor(undefined)).toBe(e);
  });

  it("distingue mayúsculas y espacios (son nombres distintos)", async () => {
    vi.resetModules();
    const m = await import("./SessionsTable.jsx");
    expect(m.processColor("App.exe")).not.toBe(m.processColor("app.exe"));
    expect(m.processColor("app.exe ")).not.toBe(m.processColor("app.exe"));
  });

  it("en un módulo nuevo: los primeros 8 nombres distintos reciben 1..8 en orden y el 9.º reutiliza 1", async () => {
    vi.resetModules();
    const m = await import("./SessionsTable.jsx");
    const got = Array.from({ length: 8 }, (_, i) => m.processColor(`p${i}`));
    expect(got).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(m.processColor("p8")).toBe(1);
    expect(m.processColor("p9")).toBe(2);
    expect(m.processColor("p0")).toBe(1); // los ya vistos conservan el suyo
    expect(m.processColor("p7")).toBe(8);
    expect(m.processColor("p8")).toBe(1);
  });

  it("repetir un nombre no consume un número nuevo", async () => {
    vi.resetModules();
    const m = await import("./SessionsTable.jsx");
    m.processColor("a"); m.processColor("a"); m.processColor("a");
    expect(m.processColor("b")).toBe(2);
  });
});

describe("SessionsTable: protocolo con color", () => {
  it("la celda es <td><span class='proto proto-x'>TEXTO</span></td> y el texto no cambia", async () => {
    api.sessions.mockResolvedValue({
      total: 5,
      items: [sess(1), sess(2, { protocol: "UDP" }), sess(3, { protocol: "ICMP" }), sess(4, { protocol: "ICMPv6" }), sess(5, { protocol: "IP-47" })],
    });
    show();
    const expected = { 1: ["TCP", "tcp"], 2: ["UDP", "udp"], 3: ["ICMP", "icmp"], 4: ["ICMPv6", "icmpv6"], 5: ["IP-47", "other"] };
    for (const [id, [text, cls]] of Object.entries(expected)) {
      const row = await rowOf(Number(id));
      const span = row.querySelector("span.proto");
      expect(span).toHaveTextContent(new RegExp(`^${text}$`));
      expect(span.className).toBe(`proto proto-${cls}`);
      expect(span.parentElement.tagName).toBe("TD");
      expect(within(row).getByText(text)).toBe(span);
    }
  });

  it("un protocolo hostil se muestra como texto y cae en 'other'", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { protocol: evil })] });
    const { container } = show();
    const row = await rowOf(1);
    expect(within(row).getByText(evil).className).toBe("proto proto-other");
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("SessionsTable: punto de color del proceso", () => {
  it("antes del nombre, aria-hidden, y el texto de la celda es solo el nombre", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 4321, name: "dot-chrome.exe" } })] });
    show({ showProcess: true });
    const row = await rowOf(1);
    const cell = within(row).getByText("dot-chrome.exe");
    expect(cell.tagName).toBe("TD");
    expect(cell.textContent).toBe("dot-chrome.exe");
    expect(cell).toHaveAttribute("title", "PID 4321");
    expect(cell.firstElementChild).toBe(dotOf(row));
    expect(dotOf(row)).toHaveAttribute("aria-hidden", "true");
    expect(dotOf(row).className).toMatch(/^dot proc-[1-8]$/);
    expect(dotOf(row).textContent).toBe("");
  });

  it("el mismo proceso en dos filas comparte clase; procesos distintos difieren", async () => {
    api.sessions.mockResolvedValue({
      total: 3,
      items: [
        sess(1, { process: { pid: 1, name: "share-a.exe" } }),
        sess(2, { process: { pid: 2, name: "share-b.exe" } }),
        sess(3, { process: { pid: 3, name: "share-a.exe" } }),
      ],
    });
    show({ showProcess: true });
    const [r1, r2, r3] = [await rowOf(1), await rowOf(2), await rowOf(3)];
    expect(dotOf(r1).className).toBe(dotOf(r3).className);
    expect(dotOf(r1).className).not.toBe(dotOf(r2).className);
    expect(dotOf(r1).className).toBe(`dot proc-${processColor("share-a.exe")}`);
  });

  it("ocho procesos distintos (nombres nuevos) tienen ocho colores distintos... mientras no se haya dado la vuelta", async () => {
    vi.resetModules();
    const { default: Fresh } = await import("./SessionsTable.jsx");
    api.sessions.mockResolvedValue({
      total: 8, items: Array.from({ length: 8 }, (_, i) => sess(i + 1, { process: { pid: i, name: `fresh-${i}` } })),
    });
    render(<Fresh refreshKey={0} filters={NONE} onFilters={() => {}} selectedId={null} onSelect={() => {}} showProcess />);
    const rows = [];
    for (let i = 1; i <= 8; i++) rows.push(await rowOf(i));
    expect(rows.map(procN)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("nombre de proceso hostil: solo texto", async () => {
    const evil = "<img src=x onerror=alert(1)>.exe";
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 9, name: evil } })] });
    const { container } = show({ showProcess: true });
    const row = await rowOf(1);
    expect(within(row).getByText(evil).textContent).toBe(evil);
    expect(container.querySelector("img")).toBeNull();
    expect(dotOf(row)).not.toBeNull();
  });

  it("proceso null: '—' sin punto; sin showProcess no hay punto", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: null })] });
    show({ showProcess: true });
    const row = await rowOf(1);
    expect(within(row).getByText("—")).toBeInTheDocument();
    expect(dotOf(row)).toBeNull();
  });

  it("sin showProcess no hay punto aunque la sesión traiga proceso", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { process: { pid: 1, name: "nodot.exe" } })] });
    show();
    expect(dotOf(await rowOf(1))).toBeNull();
  });

  it("nombre vacío o ausente no rompe", async () => {
    api.sessions.mockResolvedValue({
      total: 2, items: [sess(1, { process: { pid: 1, name: "" } }), sess(2, { process: { pid: 2 } })],
    });
    show({ showProcess: true });
    expect(procN(await rowOf(1))).toBe(procN(await rowOf(2)));
  });
});

describe("SessionsTable: clases de la fila", () => {
  const cls = (row) => row.getAttribute("class");

  it("fila normal: sin atributo class con basura (ni cadena vacía con espacios)", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1)] });
    show();
    const row = await rowOf(1);
    expect(cls(row) ?? "").toBe("");
  });

  it.each([
    ["selected", { selectedId: 1 }, {}, "selected"],
    ["ioc", {}, { ioc: ["ip:1.2.3.4"] }, "row-ioc"],
    ["reviewed", {}, { reviewed: true }, "row-reviewed"],
    ["ioc + reviewed", {}, { ioc: ["x"], reviewed: true }, "row-ioc row-reviewed"],
    ["selected + ioc", { selectedId: 1 }, { ioc: ["x"] }, "selected row-ioc"],
    ["selected + reviewed", { selectedId: 1 }, { reviewed: true }, "selected row-reviewed"],
    ["las tres", { selectedId: 1 }, { ioc: ["x"], reviewed: true }, "selected row-ioc row-reviewed"],
  ])("%s", async (_n, props, over, expected) => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, over)] });
    show(props);
    expect(cls(await rowOf(1))).toBe(expected);
  });

  it.each([
    ["ioc vacío", { ioc: [] }],
    ["ioc ausente", {}],
    ["ioc null", { ioc: null }],
    ["reviewed false", { reviewed: false }],
    ["reviewed undefined", { reviewed: undefined }],
    ["nota sin revisar", { note: "algo" }],
  ])("%s no agrega clases", async (_n, over) => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, over)] });
    show();
    expect(cls(await rowOf(1)) ?? "").toBe("");
  });

  it("solo la fila seleccionada lleva 'selected'", async () => {
    api.sessions.mockResolvedValue({ total: 3, items: [sess(1), sess(2, { ioc: ["x"] }), sess(3, { reviewed: true })] });
    show({ selectedId: 2 });
    const [r1, r2, r3] = [await rowOf(1), await rowOf(2), await rowOf(3)];
    expect([cls(r1) ?? "", cls(r2), cls(r3)]).toEqual(["", "selected row-ioc", "row-reviewed"]);
  });

  it("las marcas de texto (✓, nota, IOC) siguen apareciendo", async () => {
    api.sessions.mockResolvedValue({ total: 1, items: [sess(1, { ioc: ["x"], reviewed: true, note: "n" })] });
    show();
    const row = await rowOf(1);
    expect(within(row).getByText("✓")).toBeInTheDocument();
    expect(within(row).getByText("nota")).toBeInTheDocument();
    expect(within(row).getByText("IOC")).toBeInTheDocument();
  });
});
