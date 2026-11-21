import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { hosts: vi.fn(), graph: vi.fn() } }));
import { api } from "../../api/client.js";
import HostsView, { iconOf, nodeLabel } from "./HostsView.jsx";

const node = (ip, over = {}) => ({
  ip, kind: "publica", label: ip, name: null, role: "publica", role_label: "Servidor en internet", owner: null, note: null,
  bytes: 1000, sessions: 2, alerts: 0, ioc: false, ...over,
});
const host = (ip, over = {}) => ({
  ip, kind: "publica", role: "publica", role_label: "Servidor en internet", owner: null, note: null, sessions: 2, packets: 10, bytes: 1000,
  initiated: 1, received: 1, peers: 1, protocols: ["TCP"], services: [], name: null, alerts: 0, alert_rules: [], ioc: [], ...over,
});

// una etiqueta de un nodo solo (arriba, ancla 'middle') se corta a 16 caracteres
const cut = (t, n = 16) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);

let onError;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
});

const show = async (nodes, hosts = nodes.map((n) => host(n.ip, n))) => {
  api.graph.mockResolvedValue({ nodes, edges: [], truncated: false });
  api.hosts.mockResolvedValue({ total: hosts.length, items: hosts });
  const r = render(<HostsView refreshKey={0} onError={onError} onFilterIp={() => {}} />);
  await screen.findByRole("img");
  return r;
};
const gnode = (c, ip) => Array.from(c.querySelectorAll("g.gnode")).find((g) => g.getAttribute("aria-label").includes(`(${ip})`));

// ------------------------------------------------------------------ nodeLabel
describe("nodeLabel", () => {
  it("el nombre de la captura gana a todo lo demás", () => {
    expect(nodeLabel(node("1.2.3.4", { name: "api.example.com", owner: "Google", note: "mDNS (descubrir)" }))).toEqual({ text: "api.example.com", source: "captura" });
  });
  it("sin nombre: el dueño con la IP ('Dueño · ip')", () => {
    expect(nodeLabel(node("142.250.1.1", { owner: "Google" }))).toEqual({ text: "Google · 142.250.1.1", source: "rango" });
  });
  it("sin nombre ni dueño: la nota sin el paréntesis", () => {
    expect(nodeLabel(node("224.0.0.251", { note: "mDNS (descubrir equipos por nombre)" }))).toEqual({ text: "mDNS", source: "especial" });
    expect(nodeLabel(node("224.0.0.22", { note: "Grupo IGMP (equipos que se anotan a multicast)" })).text).toBe("Grupo IGMP");
  });
  it("una nota sin paréntesis se muestra completa", () => {
    expect(nodeLabel(node("255.255.255.255", { note: "Difusión (broadcast) a toda la red" })).text).toBe("Difusión");
    expect(nodeLabel(node("224.0.0.1", { note: "Todos los equipos de la red" })).text).toBe("Todos los equipos de la red");
  });
  it("el dueño gana a la nota", () => {
    expect(nodeLabel(node("1.2.3.4", { owner: "Apple", note: "algo (x)" })).source).toBe("rango");
  });
  it("sin nada: label y si no la IP, sin fuente", () => {
    expect(nodeLabel(node("10.0.0.1", { label: "10.0.0.1" }))).toEqual({ text: "10.0.0.1", source: null });
    expect(nodeLabel({ ip: "10.0.0.2" })).toEqual({ text: "10.0.0.2", source: null });
    expect(nodeLabel(node("10.0.0.3", { label: "otro" })).text).toBe("otro");
  });
  it("valores vacíos ('' o null) no cuentan como dato", () => {
    expect(nodeLabel(node("1.1.1.1", { name: "", owner: "", note: "" })).source).toBe(null);
    expect(nodeLabel(node("1.1.1.1", { name: null, owner: null, note: null })).source).toBe(null);
  });
  it("datos hostiles se devuelven como texto sin tocar", () => {
    const evil = "<script>alert(1)</script>";
    expect(nodeLabel(node("1.1.1.1", { name: evil })).text).toBe(evil);
    expect(nodeLabel(node("1.1.1.1", { owner: evil })).text).toBe(`${evil} · 1.1.1.1`);
  });
});

// ------------------------------------------------------------------ iconOf
describe("iconOf", () => {
  it.each([
    [{ role: "red_local" }, "red_local"], [{ role: "ipv6_local" }, "ipv6_local"], [{ role: "multicast" }, "multicast"], [{ role: "publica" }, "publica"],
  ])("%j -> %s", (n, icon) => expect(iconOf(n)).toBe(icon));
  it("nube si tiene dueño y es pública", () => expect(iconOf({ role: "publica", owner: "Google" })).toBe("nube"));
  it("un dueño en un rol que no es público no da nube", () => {
    expect(iconOf({ role: "red_local", owner: "Google" })).toBe("red_local");
    expect(iconOf({ role: "multicast", owner: "X" })).toBe("multicast");
  });
  it("rol desconocido o ausente cae a pública", () => {
    expect(iconOf({ role: "otro" })).toBe("publica");
    expect(iconOf({})).toBe("publica");
  });
  // Posible bug: iconOf busca en ICONS sin comprobar propiedad propia, así que "__proto__"/"constructor" no caen a pública.
  // El servidor solo manda 4 roles fijos; si se corrige (Object.hasOwn) quitar el `.fails`.
  it("roles heredados de Object.prototype caen a pública", () => {
    expect(iconOf({ role: "__proto__" })).toBe("publica");
    expect(iconOf({ role: "constructor" })).toBe("publica");
  });
  it("dueño vacío no es nube", () => expect(iconOf({ role: "publica", owner: "" })).toBe("publica"));
});

// ------------------------------------------------------------------ componente
describe("HostsView: dueños, íconos y leyenda", () => {
  it("el nodo muestra el nombre de la captura y NO el dueño", async () => {
    const { container } = await show([node("160.79.104.10", { name: "api.anthropic.com", owner: "Anthropic" })]);
    expect(gnode(container, "160.79.104.10").querySelector("text").textContent).toBe(cut("api.anthropic.com"));
    expect(gnode(container, "160.79.104.10")).toHaveAttribute("aria-label", "api.anthropic.com (160.79.104.10). Ver sus sesiones");
  });

  it("sin nombre: el dueño con la IP, en gris (clase gsoft), y aria-label con el mismo texto", async () => {
    const { container } = await show([node("142.250.1.1", { owner: "Google" })]);
    const g = gnode(container, "142.250.1.1");
    expect(g.querySelector("text").textContent).toBe(cut("Google · 142.250.1.1"));
    expect(g.querySelector("text")).toHaveClass("gsoft");
    expect(g).toHaveAttribute("aria-label", "Google · 142.250.1.1 (142.250.1.1). Ver sus sesiones");
  });

  it("nombre de la captura: sin clase gsoft; IP común: tampoco", async () => {
    const { container } = await show([node("1.2.3.4", { name: "a.test" }), node("5.6.7.8")]);
    expect(gnode(container, "1.2.3.4").querySelector("text")).not.toHaveClass("gsoft");
    expect(gnode(container, "5.6.7.8").querySelector("text")).not.toHaveClass("gsoft");
  });

  it("direcciones especiales: la nota va en gris", async () => {
    const { container } = await show([node("224.0.0.251", { kind: "multicast", role: "multicast", note: "mDNS (descubrir equipos por nombre)" })]);
    const g = gnode(container, "224.0.0.251");
    expect(g.querySelector("text").textContent).toBe("mDNS");
    expect(g.querySelector("text")).toHaveClass("gsoft");
  });

  it("cada nodo dibuja un ícono aria-hidden con formas fijas según el rol", async () => {
    const { container } = await show([
      node("10.0.0.1", { kind: "interna", role: "red_local" }), node("142.250.1.1", { owner: "Google" }), node("1.2.3.4"),
      node("224.0.0.251", { kind: "multicast", role: "multicast" }), node("fe80::1", { kind: "interna", role: "ipv6_local" }),
    ]);
    for (const g of container.querySelectorAll("g.gnode")) {
      const icon = g.querySelector("g.gicon");
      expect(icon).not.toBeNull();
      expect(icon).toHaveAttribute("aria-hidden", "true");
      expect(icon.children.length).toBeGreaterThan(0);
    }
    const shapes = (ip) => gnode(container, ip).querySelector("g.gicon").innerHTML;
    expect(shapes("142.250.1.1")).not.toBe(shapes("1.2.3.4")); // nube vs. globo
    expect(shapes("10.0.0.1")).not.toBe(shapes("1.2.3.4"));
    expect(new Set(["10.0.0.1", "142.250.1.1", "1.2.3.4", "224.0.0.251", "fe80::1"].map(shapes)).size).toBe(5);
  });

  it("el ícono de un dueño conocido es el de nube y el de una pública sin dueño es el globo", async () => {
    const { container } = await show([node("142.250.1.1", { owner: "Google" }), node("1.2.3.4")]);
    const cloud = gnode(container, "142.250.1.1").querySelector("g.gicon path");
    expect(cloud).not.toBeNull();
    expect(gnode(container, "1.2.3.4").querySelector("g.gicon circle")).not.toBeNull();
  });

  it("la leyenda explica los cinco dibujos con su propio ícono", async () => {
    const { container } = await show([node("1.2.3.4")]);
    const legend = screen.getByRole("list", { name: "Qué significa cada dibujo" });
    const items = within(legend).getAllByRole("listitem");
    expect(items.map((li) => li.textContent.trim())).toEqual([
      "equipo de tu red", "otro equipo del enlace (IPv6)", "multicast / difusión", "proveedor conocido", "servidor en internet"]);
    for (const li of items) {
      expect(li.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
      expect(li.querySelector("svg").children.length).toBeGreaterThan(0);
      expect(li.querySelector("svg")).toHaveAttribute("viewBox", "0 0 24 24");
      expect(li.querySelector("svg")).toHaveAttribute("width", "20");
      expect(li.querySelector("svg")).toHaveAttribute("height", "20");
    }
    expect(container.querySelectorAll(".graph-legend svg")).toHaveLength(5);
  });

  it("el pie aclara que los nombres en gris son una pista por el dueño del rango", async () => {
    await show([node("1.2.3.4")]);
    expect(screen.getByText(/Los nombres en gris claro son una pista por el dueño del rango/)).toBeInTheDocument();
  });

  // ---- tooltip
  it("tooltip del nodo: IP, rol y aclaración, sin repetir la IP cuando el texto ya la trae", async () => {
    const { container } = await show([node("142.250.1.1", { owner: "Google", role_label: "Servidor en internet" })]);
    const t = gnode(container, "142.250.1.1").querySelector("title").textContent;
    expect(t).toBe("142.250.1.1 · Servidor en internet · Dueño del rango de IP según una tabla local: es una pista, no una prueba (la nube se alquila) · 2 sesión(es) · 1000 B");
    expect(t.split("142.250.1.1")).toHaveLength(2); // aparece una sola vez
  });

  it("tooltip con nombre de la captura: IP, nombre y su origen", async () => {
    const { container } = await show([node("160.79.104.10", { name: "api.anthropic.com", owner: "Anthropic" })]);
    const t = gnode(container, "160.79.104.10").querySelector("title").textContent;
    expect(t.startsWith("160.79.104.10 · api.anthropic.com · Servidor en internet · Nombre sacado de la propia captura")).toBe(true);
    expect(t).not.toContain("Anthropic");
  });

  it("tooltip de una IP sin nada especial: IP, rol, sesiones y bytes (sin aclaración)", async () => {
    const { container } = await show([node("1.2.3.4")]);
    expect(gnode(container, "1.2.3.4").querySelector("title").textContent).toBe("1.2.3.4 · Servidor en internet · 2 sesión(es) · 1000 B");
  });

  it("tooltip de dirección especial indica que lo es", async () => {
    const { container } = await show([node("224.0.0.251", { kind: "multicast", role: "multicast", role_label: "Multicast / difusión", note: "mDNS (descubrir equipos por nombre)" })]);
    const t = gnode(container, "224.0.0.251").querySelector("title").textContent;
    expect(t).toContain("mDNS");
    expect(t).toContain("Dirección especial de la red");
  });

  it("sin role_label usa el tipo de siempre", async () => {
    const { container } = await show([node("1.2.3.4", { role_label: undefined })]);
    expect(gnode(container, "1.2.3.4").querySelector("title").textContent).toContain("Pública");
  });

  // ---- tabla
  it("tabla: la columna Tipo usa role_label y el nombre gris sale del dueño o de la nota", async () => {
    const { container } = await show([node("1.2.3.4")], [
      host("160.79.104.10", { name: "api.anthropic.com", owner: "Anthropic" }),
      host("142.250.1.1", { owner: "Google" }),
      host("224.0.0.251", { kind: "multicast", role: "multicast", role_label: "Multicast / difusión", note: "mDNS (descubrir equipos por nombre)" }),
      host("10.0.0.1", { kind: "interna", role: "red_local", role_label: "Equipo de tu red" }),
    ]);
    const rows = Array.from(container.querySelectorAll(".hosts-table tbody tr"));
    const cells = (i) => Array.from(rows[i].querySelectorAll("td")).map((c) => c.textContent);
    expect(cells(0).slice(1, 3)).toEqual(["Servidor en internet", "api.anthropic.com"]);
    expect(cells(1).slice(1, 3)).toEqual(["Servidor en internet", "Google"]);
    expect(cells(2).slice(1, 3)).toEqual(["Multicast / difusión", "mDNS (descubrir equipos por nombre)"]);
    expect(cells(3).slice(1, 3)).toEqual(["Equipo de tu red", "—"]);
  });

  it("el nombre gris del dueño lleva clase muted y el tooltip de pista; el de la captura no", async () => {
    const { container } = await show([node("1.2.3.4")], [host("142.250.1.1", { owner: "Google" }), host("160.79.104.10", { name: "a.test", owner: "Anthropic" })]);
    const rows = container.querySelectorAll(".hosts-table tbody tr");
    const grey = within(rows[0]).getByText("Google");
    expect(grey).toHaveClass("muted");
    expect(grey.getAttribute("title")).toMatch(/pista, no una prueba/);
    expect(within(rows[1]).getByText("a.test").className).not.toContain("muted");
    expect(within(rows[1]).queryByText("Anthropic")).toBeNull();
  });

  it("host sin role_label cae al tipo clásico", async () => {
    const { container } = await show([node("1.2.3.4")], [host("1.2.3.4", { role_label: "", kind: "publica" })]);
    expect(container.querySelector(".hosts-table tbody tr td:nth-child(2)").textContent).toBe("Pública");
  });

  // ---- hostil
  it("dueño, nota, nombre y rol hostiles se muestran como texto en el grafo y en la tabla", async () => {
    const evil = "<script>alert(1)</script>";
    const { container } = await show(
      [node("1.1.1.1", { owner: evil }), node("2.2.2.2", { note: evil, kind: "multicast", role: "multicast" }), node("3.3.3.3", { name: evil })],
      [host("1.1.1.1", { owner: evil, role_label: evil }), host("2.2.2.2", { note: evil }), host("3.3.3.3", { name: evil })],
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(gnode(container, "3.3.3.3").querySelector("text").textContent).toContain("<script>");
    expect(within(container.querySelector(".hosts-table")).getAllByText(evil).length).toBeGreaterThanOrEqual(2);
  });

  it("clic y teclado siguen entregando solo la IP", async () => {
    const onFilterIp = vi.fn();
    api.graph.mockResolvedValue({ nodes: [node("142.250.1.1", { owner: "Google" })], edges: [], truncated: false });
    api.hosts.mockResolvedValue({ total: 1, items: [host("142.250.1.1", { owner: "Google" })] });
    const { container } = render(<HostsView refreshKey={0} onError={onError} onFilterIp={onFilterIp} />);
    await screen.findByRole("img");
    await userEvent.click(gnode(container, "142.250.1.1"));
    expect(onFilterIp).toHaveBeenCalledWith("142.250.1.1");
  });

  it("nodos de respuestas viejas (sin campos nuevos) siguen funcionando", async () => {
    const old = { ip: "8.8.8.8", kind: "publica", label: "dns.google", bytes: 1, sessions: 1, alerts: 0, ioc: false };
    const { container } = await show([old], [host("8.8.8.8", { role: undefined, role_label: undefined, owner: undefined, note: undefined })]);
    expect(gnode(container, "8.8.8.8").querySelector("text").textContent).toBe("dns.google");
    expect(gnode(container, "8.8.8.8").querySelector("g.gicon")).not.toBeNull();
    expect(container.innerHTML).not.toMatch(/undefined|NaN/);
  });
});
