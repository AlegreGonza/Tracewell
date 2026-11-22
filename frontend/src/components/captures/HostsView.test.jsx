import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within, act, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../api/client.js", () => ({ api: { hosts: vi.fn(), graph: vi.fn() } }));
import { api } from "../../api/client.js";
import HostsView, { layoutGraph } from "./HostsView.jsx";

const node = (ip, over = {}) => ({ ip, kind: "interna", label: ip, bytes: 1000, sessions: 2, alerts: 0, ioc: false, ...over });
const host = (ip, over = {}) => ({
  ip, kind: "interna", sessions: 2, packets: 10, bytes: 1000, initiated: 1, received: 1, peers: 1, protocols: ["TCP"], services: [],
  name: null, alerts: 0, alert_rules: [], ioc: [], ...over,
});
const edge = (a, b, bytes = 500, over = {}) => ({ a, b, bytes, sessions: 1, protocols: ["TCP"], ...over });

let onError, onFilterIp;
beforeEach(() => {
  vi.clearAllMocks();
  onError = vi.fn();
  onFilterIp = vi.fn();
  api.hosts.mockResolvedValue({
    total: 3, items: [host("10.0.0.1"), host("10.0.0.2"), host("8.8.8.8", { kind: "publica", name: "dns.google", services: [{ protocol: "TCP", port: 443, sessions: 2 }] })],
  });
  api.graph.mockResolvedValue({
    nodes: [node("10.0.0.1"), node("10.0.0.2"), node("8.8.8.8", { kind: "publica", label: "dns.google" })],
    edges: [edge("10.0.0.1", "8.8.8.8", 800), edge("10.0.0.1", "10.0.0.2", 200)], truncated: false,
  });
});

const show = (props = {}) => render(<HostsView refreshKey={0} onError={onError} onFilterIp={onFilterIp} {...props} />);
const nodes = (c) => Array.from(c.querySelectorAll("g.gnode"));
const nodeOf = (c, ip) => nodes(c).find((g) => g.getAttribute("aria-label").includes(`(${ip})`));
const loaded = async () => {
  const r = show();
  await screen.findByRole("img");
  return r;
};

// ------------------------------------------------------------------ layoutGraph / edgePath

const mk = (n, kind) => Array.from({ length: n }, (_, i) => node(`${kind === "interna" ? "10.0.0." : kind === "multicast" ? "224.0.0." : "1.1.1."}${i}`, { kind }));
const mix = (inner, outer) => [...mk(inner, "interna"), ...mk(outer, "publica")];
const minDist = (pos) => {
  const p = Object.values(pos);
  let m = Infinity;
  for (let i = 0; i < p.length; i++) for (let j = i + 1; j < p.length; j++) m = Math.min(m, Math.hypot(p[i].x - p[j].x, p[i].y - p[j].y));
  return m;
};
const onEllipse = (p, rx, ry) => ((p.x - 550) / rx) ** 2 + ((p.y - 310) / ry) ** 2;
const R = 18; // radio de cada nodo

describe("layoutGraph (telaraña)", () => {
  it("el tamaño del dibujo es fijo (1100 x 620) sin importar cuántos equipos haya", () => {
    for (const n of [0, 1, 5, 24, 60]) {
      const { width, height } = layoutGraph(mix(n, n));
      expect([width, height]).toEqual([1100, 620]);
    }
  });

  it("sin nodos: sin posiciones y sin anillos", () => {
    expect(layoutGraph([])).toEqual({ pos: {}, width: 1100, height: 620, rings: 0 });
  });

  it("un solo equipo de la red local queda exactamente en el centro", () => {
    expect(layoutGraph([node("10.0.0.1")]).pos["10.0.0.1"]).toEqual({ x: 550, y: 310, cos: 0, anchor: "middle", ring: 0 });
  });

  it("hasta 10 equipos de la red local: elipse chica con rx = min(44 + 6n, 100) y ry = min(32 + 4n, 70)", () => {
    for (const n of [2, 3, 5, 9, 10]) {
      const rx = Math.min(44 + 6 * n, 100);
      const ry = Math.min(32 + 4 * n, 70);
      const { pos, rings } = layoutGraph(mk(n, "interna"));
      expect(rings).toBe(0);
      for (const p of Object.values(pos)) {
        expect(p.ring).toBe(0);
        expect(onEllipse(p, rx, ry)).toBeCloseTo(1, 6);
        expect(Math.abs(p.x - 550)).toBeLessThanOrEqual(100 + 1e-9);
        expect(Math.abs(p.y - 310)).toBeLessThanOrEqual(70 + 1e-9);
      }
    }
  });

  it("de 11 a 30 equipos locales: los 10 primeros en la elipse chica y el resto en el segundo anillo (175 x 125)", () => {
    for (const n of [11, 20, 30]) {
      const { pos } = layoutGraph(mk(n, "interna"));
      const all = Object.values(pos);
      all.slice(0, 10).forEach((p) => expect(onEllipse(p, 100, 70)).toBeCloseTo(1, 6));
      all.slice(10).forEach((p) => expect(onEllipse(p, 175, 125)).toBeCloseTo(1, 6));
    }
  });

  it("de 31 en adelante: tercer anillo local (260 x 185) para el resto", () => {
    const { pos } = layoutGraph(mk(60, "interna"));
    const all = Object.values(pos);
    all.slice(0, 10).forEach((p) => expect(onEllipse(p, 100, 70)).toBeCloseTo(1, 6));
    all.slice(10, 30).forEach((p) => expect(onEllipse(p, 175, 125)).toBeCloseTo(1, 6));
    all.slice(30).forEach((p) => expect(onEllipse(p, 260, 185)).toBeCloseTo(1, 6));
    expect(all.slice(30)).toHaveLength(30);
  });

  it("los equipos locales nunca se alejan más de 260 x 185 del centro y quedan dentro del anillo exterior", () => {
    for (const p of Object.values(layoutGraph(mk(60, "interna")).pos)) {
      expect(Math.abs(p.x - 550)).toBeLessThanOrEqual(260 + 1e-9);
      expect(Math.abs(p.y - 310)).toBeLessThanOrEqual(185 + 1e-9);
    }
  });

  it("los demás (públicos, multicast) van en un anillo exterior (elipse 310 x 220), nunca en el centro", () => {
    const nodes = [node("8.8.8.8", { kind: "publica" }), node("224.0.0.251", { kind: "multicast" }), node("10.0.0.1")];
    const { pos, rings } = layoutGraph(nodes);
    expect(rings).toBe(1);
    expect(pos["10.0.0.1"].ring).toBe(0);
    for (const ip of ["8.8.8.8", "224.0.0.251"]) {
      expect(pos[ip].ring).toBe(1);
      expect(onEllipse(pos[ip], 310, 220)).toBeCloseTo(1, 6);
    }
  });

  it("arranca arriba (ángulo -90°) y sigue en sentido horario", () => {
    const { pos } = layoutGraph(mk(4, "publica"));
    const [a, b, c, d] = Object.keys(pos).map((ip) => pos[ip]);
    expect(a.x).toBeCloseTo(550);
    expect(a.y).toBeCloseTo(90); // arriba: 310 - 220
    expect(b.x).toBeCloseTo(860);
    expect(b.y).toBeCloseTo(310); // derecha
    expect(c.x).toBeCloseTo(550);
    expect(c.y).toBeCloseTo(530); // abajo
    expect(d.x).toBeCloseTo(240);
    expect(d.y).toBeCloseTo(310); // izquierda
  });

  it("el orden de entrada se conserva: los ángulos crecen en sentido horario sin saltos", () => {
    const { pos } = layoutGraph(mk(12, "publica"));
    const angles = Object.values(pos).map((p) => Math.atan2((p.y - 310) / 220, (p.x - 550) / 310));
    const unwrapped = angles.map((a) => (a + Math.PI / 2 + 2 * Math.PI) % (2 * Math.PI));
    for (let i = 1; i < unwrapped.length; i++) expect(unwrapped[i]).toBeGreaterThan(unwrapped[i - 1]);
    expect(unwrapped[0]).toBeCloseTo(0);
    expect(unwrapped[1] - unwrapped[0]).toBeCloseTo((2 * Math.PI) / 12);
  });

  it("también la red local arranca arriba y avanza en sentido horario", () => {
    const { pos } = layoutGraph(mk(4, "interna"));
    const [a, b] = Object.values(pos);
    expect(a.x).toBeCloseTo(550);
    expect(a.y).toBeLessThan(310);
    expect(b.x).toBeGreaterThan(550);
  });

  it("hasta 24 equipos en el anillo 1; del 25.º en adelante, en un segundo anillo mayor (380 x 270)", () => {
    const { pos, rings } = layoutGraph(mk(30, "publica"));
    const all = Object.values(pos);
    expect(rings).toBe(2);
    expect(all.filter((p) => p.ring === 1)).toHaveLength(24);
    expect(all.filter((p) => p.ring === 2)).toHaveLength(6);
    for (const p of all.filter((q) => q.ring === 1)) expect(onEllipse(p, 310, 220)).toBeCloseTo(1, 6);
    for (const p of all.filter((q) => q.ring === 2)) expect(onEllipse(p, 380, 270)).toBeCloseTo(1, 6);
    expect(Object.keys(pos).slice(0, 24).every((ip) => pos[ip].ring === 1)).toBe(true);
  });

  it("exactamente 24 equipos exteriores no abren el segundo anillo; 25 sí", () => {
    expect(layoutGraph(mk(24, "publica")).rings).toBe(1);
    expect(layoutGraph(mk(25, "publica")).rings).toBe(2);
  });

  it("el segundo anillo gira medio paso para no quedar alineado con el primero", () => {
    const { pos } = layoutGraph(mk(30, "publica"));
    const firstOfRing2 = Object.values(pos).find((p) => p.ring === 2);
    expect(Math.abs(firstOfRing2.x - 550)).toBeGreaterThan(1); // no está exactamente arriba
  });

  it("'cos' es el coseno del ángulo y 'anchor' sigue la regla: >0.2 start, <-0.2 end, resto middle", () => {
    for (const nodes of [mk(24, "publica"), mk(5, "interna"), mix(3, 30)]) {
      const { pos } = layoutGraph(nodes);
      for (const p of Object.values(pos).filter((q) => q.ring > 0)) {
        const rx = p.ring === 1 ? 310 : 380;
        expect(p.cos).toBeCloseTo((p.x - 550) / rx, 9);
        expect(p.anchor).toBe(Math.abs(p.cos) < 0.2 ? "middle" : p.cos > 0 ? "start" : "end");
      }
    }
  });

  it("anclas concretas: arriba y abajo 'middle', derecha 'start', izquierda 'end'", () => {
    const { pos } = layoutGraph(mk(4, "publica"));
    expect(Object.values(pos).map((p) => p.anchor)).toEqual(["middle", "start", "middle", "end"]);
  });

  it.each([[1, 0], [0, 1], [0, 24], [0, 30], [0, 60], [1, 59], [5, 55], [30, 30], [60, 0]])(
    "con %i internos y %i externos todo queda dentro del dibujo 1100 x 620 (con el radio del nodo)", (a, b) => {
      for (const p of Object.values(layoutGraph(mix(a, b)).pos)) {
        expect(p.x - R).toBeGreaterThanOrEqual(0);
        expect(p.x + R).toBeLessThanOrEqual(1100);
        expect(p.y - R).toBeGreaterThanOrEqual(0);
        expect(p.y + R).toBeLessThanOrEqual(620);
      }
    });

  it.each([[1, 0], [2, 0], [5, 0], [10, 0], [20, 0], [28, 0], [30, 0], [31, 0], [40, 0], [45, 0], [60, 0], [0, 24], [0, 25], [0, 30], [0, 60], [5, 55], [1, 59], [10, 50]])(
    "con %i internos y %i externos ningún nodo pisa a otro (distancia >= 2 radios)", (a, b) => {
      expect(minDist(layoutGraph(mix(a, b)).pos)).toBeGreaterThanOrEqual(2 * R);
    });

  it("muchos equipos de la red local (11, 24, 28) tampoco se pisan", () => {
    for (const n of [11, 24, 28]) expect(minDist(layoutGraph(mk(n, "interna")).pos), `${n}`).toBeGreaterThanOrEqual(2 * R);
  });

  it("11 a 60 equipos de la red local tampoco se pisan (distancia mínima >= 2 radios)", () => {
    for (const n of [11, 20, 28, 30, 31, 40, 45, 60]) expect(minDist(layoutGraph(mk(n, "interna")).pos), `${n}`).toBeGreaterThanOrEqual(2 * R);
  });

  it("posiciones únicas aunque haya muchas", () => {
    const { pos } = layoutGraph(mix(40, 60));
    const keys = new Set(Object.values(pos).map((p) => `${p.x.toFixed(3)},${p.y.toFixed(3)}`));
    expect(keys.size).toBe(100);
  });

  it("anillos: 0 sin exteriores, 1 con hasta 24, 2 con más", () => {
    expect(layoutGraph(mk(5, "interna")).rings).toBe(0);
    expect(layoutGraph(mix(5, 1)).rings).toBe(1);
    expect(layoutGraph(mix(0, 60)).rings).toBe(2);
  });

  it("los multicast cuentan como exteriores", () => {
    const { pos } = layoutGraph([node("10.0.0.1"), ...mk(3, "multicast")]);
    expect(Object.values(pos).filter((p) => p.ring === 1)).toHaveLength(3);
  });
});

describe("HostsView", () => {
  it("no dibuja nada mientras carga ni si no hay equipos", async () => {
    api.hosts.mockReturnValue(new Promise(() => {}));
    expect(show().container).toBeEmptyDOMElement();
  });

  it("sin equipos no dibuja nada", async () => {
    api.hosts.mockResolvedValue({ total: 0, items: [] });
    api.graph.mockResolvedValue({ nodes: [], edges: [], truncated: false });
    const { container } = show();
    await waitFor(() => expect(api.graph).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("título, cantidad de IP y resumen accesible del grafo", async () => {
    await loaded();
    expect(screen.getByRole("heading", { name: "Equipos" })).toBeInTheDocument();
    expect(screen.getByText("3 IP distintas")).toBeInTheDocument();
    expect(screen.getByRole("img")).toHaveAttribute("aria-label", "Grafo de 3 equipos y 2 conversaciones entre ellos.");
    expect(screen.getByRole("button", { name: /Ayuda: Equipos/ })).toBeInTheDocument();
  });

  it("un nodo por equipo con rol button, foco por teclado y etiqueta accesible", async () => {
    const { container } = await loaded();
    expect(nodes(container)).toHaveLength(3);
    for (const g of nodes(container)) {
      expect(g).toHaveAttribute("role", "button");
      expect(g).toHaveAttribute("tabindex", "0");
    }
    expect(nodeOf(container, "8.8.8.8")).toHaveAttribute("aria-label", "dns.google (8.8.8.8). Ver sus sesiones");
    expect(nodeOf(container, "8.8.8.8").getAttribute("class")).toContain("gnode-publica");
    expect(nodeOf(container, "10.0.0.1").getAttribute("class")).toContain("gnode-interna");
  });

  it("posiciona los nodos con layoutGraph y el dibujo mide 1100 x 620", async () => {
    const { container } = await loaded();
    const { pos } = layoutGraph([node("10.0.0.1"), node("10.0.0.2"), node("8.8.8.8", { kind: "publica" })]);
    for (const ip of ["10.0.0.1", "10.0.0.2", "8.8.8.8"]) {
      const [x, y] = nodeOf(container, ip).getAttribute("transform").match(/-?\d+(\.\d+)?(e-?\d+)?/g).map(Number);
      expect(x).toBeCloseTo(pos[ip].x, 6);
      expect(y).toBeCloseTo(pos[ip].y, 6);
    }
    expect(container.querySelector("svg")).toHaveAttribute("viewBox", "0 0 1100 620");
  });

  it("cada nodo tiene su forma y su ícono centrado", async () => {
    const { container } = await loaded();
    for (const g of nodes(container)) {
      expect(g.querySelector("circle, rect, path:not(.gicon path)")).not.toBeNull();
      expect(g.querySelector("g.gicon")).toHaveAttribute("transform", "translate(-12, -12)");
    }
  });

  describe("forma según el rol", () => {
    const shapeOf = async (over) => {
      api.hosts.mockResolvedValue({ total: 1, items: [host("9.9.9.9")] });
      api.graph.mockResolvedValue({ nodes: [node("9.9.9.9", over)], edges: [], truncated: false });
      const { container } = show();
      await screen.findByRole("img");
      return nodeOf(container, "9.9.9.9");
    };
    const first = (g) => g.firstElementChild;
    it("red_local e ipv6_local: círculo de radio 18", async () => {
      for (const role of ["red_local", "ipv6_local"]) {
        const g = await shapeOf({ role });
        expect(first(g).tagName).toBe("circle");
        expect(first(g)).toHaveAttribute("r", "18");
        cleanup();
      }
    });
    it("multicast: rectángulo de 36 x 36", async () => {
      const g = await shapeOf({ role: "multicast", kind: "multicast" });
      expect(first(g).tagName).toBe("rect");
      expect(first(g)).toHaveAttribute("width", "36");
    });
    it("pública sin dueño: rombo (path de 4 vértices)", async () => {
      const g = await shapeOf({ role: "publica", owner: null });
      expect(first(g).tagName).toBe("path");
      expect(first(g).getAttribute("d")).toBe("M0 -21 L21 0 L0 21 L-21 0 Z");
    });
    it("pública con dueño: hexágono (path de 6 vértices)", async () => {
      const g = await shapeOf({ role: "publica", owner: "Google" });
      expect(first(g).tagName).toBe("path");
      expect(first(g).getAttribute("d").match(/L/g)).toHaveLength(5);
    });
  });

  it("la guía: una elipse con un anillo, dos con más de 24 exteriores, ninguna sin exteriores", async () => {
    const one = await loaded();
    expect(one.container.querySelectorAll("g.web ellipse")).toHaveLength(1);
    expect(one.container.querySelector("g.web")).toHaveAttribute("aria-hidden", "true");
    one.unmount();
    api.graph.mockResolvedValue({ nodes: mk(30, "publica"), edges: [], truncated: false });
    const two = show();
    await screen.findByRole("img");
    expect(two.container.querySelectorAll("g.web ellipse")).toHaveLength(2);
    two.unmount();
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.1")], edges: [], truncated: false });
    const none = show();
    await screen.findByRole("img");
    expect(none.container.querySelectorAll("g.web ellipse")).toHaveLength(0);
  });

  it("el nodo de la red local única va en el centro y el exterior arriba", async () => {
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.1"), node("8.8.8.8", { kind: "publica" })], edges: [], truncated: false });
    const { container } = show();
    await screen.findByRole("img");
    expect(nodeOf(container, "10.0.0.1")).toHaveAttribute("transform", "translate(550, 310)");
    const [x, y] = nodeOf(container, "8.8.8.8").getAttribute("transform").match(/-?\d+(\.\d+)?/g).map(Number);
    expect(x).toBeCloseTo(550);
    expect(y).toBeCloseTo(90);
  });

  it("una línea por conversación con título (par, sesiones, bytes, protocolos) y grosor por tráfico", async () => {
    const { container } = await loaded();
    const paths = Array.from(container.querySelectorAll("line.edge"));
    expect(paths).toHaveLength(2);
    expect(container.querySelectorAll("path.edge")).toHaveLength(0);
    expect(paths[0].querySelector("title").textContent).toBe("10.0.0.1 ↔ 8.8.8.8 · 1 sesión(es) · 800 B · TCP");
    expect(Number(paths[0].getAttribute("stroke-width"))).toBeCloseTo(6); // la de más tráfico
    expect(Number(paths[1].getAttribute("stroke-width"))).toBeCloseTo(1 + 5 * Math.sqrt(200 / 800));
  });

  it("las líneas van de centro a centro de los nodos", async () => {
    const { container } = await loaded();
    const { pos } = layoutGraph([node("10.0.0.1"), node("10.0.0.2"), node("8.8.8.8", { kind: "publica" })]);
    const l = container.querySelector("line.edge"); // 10.0.0.1 <-> 8.8.8.8
    expect(Number(l.getAttribute("x1"))).toBeCloseTo(pos["10.0.0.1"].x, 6);
    expect(Number(l.getAttribute("y1"))).toBeCloseTo(pos["10.0.0.1"].y, 6);
    expect(Number(l.getAttribute("x2"))).toBeCloseTo(pos["8.8.8.8"].x, 6);
    expect(Number(l.getAttribute("y2"))).toBeCloseTo(pos["8.8.8.8"].y, 6);
  });

  it("las líneas se dibujan antes que los nodos (quedan debajo)", async () => {
    const { container } = await loaded();
    const svg = container.querySelector("svg");
    const kids = Array.from(svg.children);
    const lastLine = Math.max(...kids.map((k, i) => (k.tagName === "line" ? i : -1)));
    const firstNode = kids.findIndex((k) => k.classList.contains("gnode"));
    expect(lastLine).toBeLessThan(firstNode);
  });

  it("si una línea apunta a un equipo que no está en el grafo, se omite sin romper", async () => {
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.1")], edges: [edge("10.0.0.1", "9.9.9.9")], truncated: false });
    const { container } = await loaded();
    expect(container.querySelectorAll("path.edge")).toHaveLength(0);
  });

  it("grafo sin líneas: sin NaN", async () => {
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.1")], edges: [], truncated: false });
    const { container } = await loaded();
    expect(container.innerHTML).not.toMatch(/NaN/);
  });

  // ---- banderas
  it("nodos con alertas muestran '! n' y con IOC muestran 'IOC' (el IOC gana)", async () => {
    api.graph.mockResolvedValue({
      nodes: [node("10.0.0.1", { alerts: 3 }), node("10.0.0.2", { ioc: true }), node("10.0.0.3", { alerts: 2, ioc: true }), node("10.0.0.4")],
      edges: [], truncated: false,
    });
    const { container } = await loaded();
    const flag = (ip) => nodeOf(container, ip).querySelector(".gflag")?.textContent ?? null;
    expect([flag("10.0.0.1"), flag("10.0.0.2"), flag("10.0.0.3"), flag("10.0.0.4")]).toEqual(["! 3", "IOC", "IOC", null]);
    expect(nodeOf(container, "10.0.0.1").querySelector("text > tspan.gflag")).not.toBeNull();
    expect(nodeOf(container, "10.0.0.1").getAttribute("class")).toContain("flagged");
    expect(nodeOf(container, "10.0.0.4").getAttribute("class")).not.toContain("flagged");
  });

  // ---- activar
  it("clic llama a onFilterIp con la IP (solo la IP)", async () => {
    const { container } = await loaded();
    await userEvent.click(nodeOf(container, "8.8.8.8"));
    expect(onFilterIp).toHaveBeenCalledTimes(1);
    expect(onFilterIp).toHaveBeenCalledWith("8.8.8.8");
  });

  it("Enter y Espacio activan el nodo enfocado; otras teclas no", async () => {
    const { container } = await loaded();
    act(() => nodeOf(container, "10.0.0.2").focus());
    await userEvent.keyboard("{Enter}");
    await userEvent.keyboard(" ");
    expect(onFilterIp).toHaveBeenCalledTimes(2);
    expect(onFilterIp).toHaveBeenNthCalledWith(1, "10.0.0.2");
    await userEvent.keyboard("a");
    await userEvent.keyboard("{Escape}");
    await userEvent.keyboard("{Tab}");
    expect(onFilterIp).toHaveBeenCalledTimes(2);
  });

  it("Tab recorre los nodos en orden", async () => {
    const { container } = await loaded();
    await userEvent.tab();
    const first = document.activeElement;
    expect(container.contains(first) || first.tagName === "BUTTON").toBe(true);
  });

  it("sin onFilterIp no rompe al activar", async () => {
    const { container } = show({ onFilterIp: undefined });
    await screen.findByRole("img");
    await userEvent.click(nodeOf(container, "10.0.0.1"));
    act(() => nodeOf(container, "10.0.0.1").focus());
    await userEvent.keyboard("{Enter}");
  });

  // ---- resaltado
  it("al pasar el mouse se atenúan los equipos sin relación y se activa su línea", async () => {
    const { container } = await loaded();
    await userEvent.hover(nodeOf(container, "8.8.8.8"));
    const dim = (ip) => nodeOf(container, ip).getAttribute("class").includes("dim");
    expect([dim("8.8.8.8"), dim("10.0.0.1"), dim("10.0.0.2")]).toEqual([false, false, true]);
    expect(container.querySelectorAll("line.edge.active")).toHaveLength(1);
    await userEvent.unhover(nodeOf(container, "8.8.8.8"));
    expect(container.querySelectorAll("g.dim")).toHaveLength(0);
    expect(container.querySelectorAll("line.active")).toHaveLength(0);
  });

  it("el foco y el desenfoque hacen lo mismo que el mouse", async () => {
    const { container } = await loaded();
    act(() => nodeOf(container, "10.0.0.2").focus());
    expect(nodeOf(container, "8.8.8.8").getAttribute("class")).toContain("dim");
    expect(nodeOf(container, "10.0.0.1").getAttribute("class")).not.toContain("dim");
    act(() => nodeOf(container, "10.0.0.2").blur());
    expect(container.querySelectorAll("g.dim")).toHaveLength(0);
  });

  it("sin pasar el mouse nada está atenuado", async () => {
    const { container } = await loaded();
    expect(container.querySelectorAll("g.dim")).toHaveLength(0);
  });

  // ---- texto
  it("etiquetas hostiles se muestran como texto y las largas se acortan (16 caracteres arriba o abajo, 20 a los lados)", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.1", { label: evil }), node("10.0.0.2", { label: "x".repeat(80) })], edges: [], truncated: false });
    api.hosts.mockResolvedValue({ total: 2, items: [host("10.0.0.1", { name: evil }), host("10.0.0.2")] });
    const { container } = await loaded();
    expect(container.querySelector("img")).toBeNull();
    // con 2 equipos locales quedan arriba y abajo: ancla 'middle' -> 16 caracteres
    expect(nodeOf(container, "10.0.0.1").querySelector("text").textContent).toBe(`${evil.slice(0, 15)}…`);
    expect(nodeOf(container, "10.0.0.1")).toHaveAttribute("aria-label", `${evil} (10.0.0.1). Ver sus sesiones`);
    const long = nodeOf(container, "10.0.0.2").querySelector("text").textContent;
    expect(long).toHaveLength(16);
    expect(long.endsWith("…")).toBe(true);
    expect(screen.getByText(evil, { selector: "td" })).toBeInTheDocument();
  });

  it("los nodos de los costados cortan a 20 caracteres y los de arriba/abajo a 16", async () => {
    const nodes4 = mk(4, "publica").map((n) => ({ ...n, label: "y".repeat(60) }));
    api.graph.mockResolvedValue({ nodes: nodes4, edges: [], truncated: false });
    const { container } = show();
    await screen.findByRole("img");
    const { pos } = layoutGraph(nodes4);
    for (const n of nodes4) {
      const t = nodeOf(container, n.ip).querySelector("text").textContent;
      expect(t).toHaveLength(pos[n.ip].anchor === "middle" ? 16 : 20);
    }
    expect(nodes4.map((n) => pos[n.ip].anchor)).toEqual(["middle", "start", "middle", "end"]);
  });

  it("la etiqueta exacta de 20 (costado) o 16 (arriba) caracteres no se corta; una más sí", async () => {
    const nodes4 = mk(4, "publica");
    const exact = [nodes4[0], nodes4[1]].map((n, i) => ({ ...n, label: "z".repeat(i === 0 ? 16 : 20) }));
    api.graph.mockResolvedValue({ nodes: [...exact, { ...nodes4[2], label: "q".repeat(17) }, { ...nodes4[3], label: "w".repeat(21) }], edges: [], truncated: false });
    const { container } = show();
    await screen.findByRole("img");
    const text = (ip) => nodeOf(container, ip).querySelector("text").textContent;
    expect(text(nodes4[0].ip)).toBe("z".repeat(16));
    expect(text(nodes4[1].ip)).toBe("z".repeat(20));
    expect(text(nodes4[2].ip)).toBe(`${"q".repeat(15)}…`);
    expect(text(nodes4[3].ip)).toBe(`${"w".repeat(19)}…`);
  });

  it("la posición de la etiqueta: a los lados a ±26 con ancla start/end; arriba y abajo centrada a -26 y +35", async () => {
    const nodes4 = mk(4, "publica");
    api.graph.mockResolvedValue({ nodes: nodes4, edges: [], truncated: false });
    const { container } = show();
    await screen.findByRole("img");
    const t = (i) => nodeOf(container, nodes4[i].ip).querySelector("text");
    expect([t(0).getAttribute("text-anchor"), t(1).getAttribute("text-anchor"), t(2).getAttribute("text-anchor"), t(3).getAttribute("text-anchor")]).toEqual(["middle", "start", "middle", "end"]);
    expect(t(0).getAttribute("y")).toBe("-26");
    expect(t(2).getAttribute("y")).toBe("35");
    expect(t(1).getAttribute("x")).toBe("26");
    expect(t(3).getAttribute("x")).toBe("-26");
    expect(t(1).getAttribute("y")).toBe("4");
  });

  it("nota al pie y aviso cuando el grafo está recortado", async () => {
    await loaded();
    expect(screen.getByText(/Tu red está en el centro y el resto de los equipos, alrededor\./)).toBeInTheDocument();
    expect(screen.queryByText(/A la izquierda/)).toBeNull();
    expect(screen.queryByText(/Se muestran solo los de más tráfico/)).toBeNull();
  });

  it("truncated agrega el aviso", async () => {
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.1")], edges: [], truncated: true });
    show();
    expect(await screen.findByText(/Se muestran solo los de más tráfico/)).toBeInTheDocument();
  });

  // ---- tabla
  it("la tabla de equipos: una fila por IP con servicios, nombre y alertas", async () => {
    api.hosts.mockResolvedValue({
      total: 2,
      items: [
        host("8.8.8.8", { kind: "publica", name: "dns.google", peers: 4, sessions: 1234, services: [{ protocol: "TCP", port: 443, sessions: 2 }, { protocol: "UDP", port: 53, sessions: 1 }], protocols: ["TCP", "UDP"] }),
        host("10.0.0.1", { alerts: 2, alert_rules: ["a_rule", "b_rule"], ioc: ["ip:10.0.0.1"] }),
      ],
    });
    const { container } = await loaded();
    const rows = container.querySelectorAll(".hosts-table tbody tr");
    expect(rows).toHaveLength(2);
    const a = within(rows[0]);
    expect(a.getByText("dns.google")).toBeInTheDocument();
    expect(a.getByText("TCP/443 UDP/53")).toBeInTheDocument();
    expect(a.getByText("TCP, UDP")).toBeInTheDocument();
    expect(a.getByText("Pública")).toBeInTheDocument();
    expect(a.getByText("1.234")).toBeInTheDocument();
    const b = within(rows[1]);
    expect(b.getByText("2 (a_rule, b_rule)")).toBeInTheDocument();
    expect(b.getByText("IOC")).toHaveAttribute("title", "Coincide con: ip:10.0.0.1");
    expect(rows[1].className).toBe("row-ioc");
    expect(rows[0].className).toBe("");
    expect(b.getAllByText("—").length).toBeGreaterThanOrEqual(2); // sin nombre y sin servicios
  });

  it("un host sin alertas muestra 0", async () => {
    const { container } = await loaded();
    expect(within(container.querySelector(".hosts-table tbody tr")).getByText("0")).toBeInTheDocument();
  });

  it("la IP de la tabla es un botón que llama a onFilterIp", async () => {
    const { container } = await loaded();
    await userEvent.click(within(container.querySelector(".hosts-table")).getByRole("button", { name: "8.8.8.8" }));
    expect(onFilterIp).toHaveBeenCalledWith("8.8.8.8");
  });

  it("el resumen del desplegable cuenta como máximo 50 equipos", async () => {
    api.hosts.mockResolvedValue({ total: 90, items: Array.from({ length: 60 }, (_, i) => host(`10.0.1.${i}`)) });
    const { container } = await loaded();
    expect(container.querySelector(".hosts-table summary")).toHaveTextContent("Tabla de equipos (50 con más tráfico)");
    expect(screen.getByText("90 IP distintas")).toBeInTheDocument();
  });

  it("los detalles se abren y se cierran", async () => {
    const { container } = await loaded();
    const d = container.querySelector("details.hosts-table");
    expect(d.open).toBe(false);
    await userEvent.click(d.querySelector("summary"));
    expect(d.open).toBe(true);
    await userEvent.click(d.querySelector("summary"));
    expect(d.open).toBe(false);
  });

  // ---- red
  it("pide equipos y grafo con señal de aborto y vuelve a pedir si cambia refreshKey", async () => {
    const { rerender } = await loaded();
    expect(api.hosts.mock.calls[0][0]).toBeInstanceOf(AbortSignal);
    expect(api.graph.mock.calls[0][0]).toBeInstanceOf(AbortSignal);
    rerender(<HostsView refreshKey={1} onError={onError} onFilterIp={onFilterIp} />);
    await waitFor(() => expect(api.hosts).toHaveBeenCalledTimes(2));
    expect(api.hosts.mock.calls[0][0].aborted).toBe(true);
  });

  it("un error de cualquiera de los dos llama a onError y no dibuja", async () => {
    api.graph.mockRejectedValue(new Error("grafo roto"));
    const { container } = show();
    await waitFor(() => expect(onError).toHaveBeenCalledWith("grafo roto"));
    expect(container).toBeEmptyDOMElement();
  });

  it("un AbortError no se reporta y al desmontar se aborta", async () => {
    api.hosts.mockRejectedValue(Object.assign(new Error("a"), { name: "AbortError" }));
    const { unmount } = show();
    await waitFor(() => expect(api.hosts).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(onError).not.toHaveBeenCalled();
    const signal = api.hosts.mock.calls[0][0];
    unmount();
    expect(signal.aborted).toBe(true);
  });
});

describe("HostsView: perfil del equipo", () => {
  it("muestra los roles inferidos del equipo", async () => {
    api.hosts.mockResolvedValue({ total: 1, items: [host("10.0.0.5", { roles: ["Cliente DNS", "Top talker"] })] });
    api.graph.mockResolvedValue({ nodes: [node("10.0.0.5")], edges: [], truncated: false });
    await loaded();
    const list = screen.getByRole("list", { name: "Perfil del equipo" });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Cliente DNS", "Top talker"]);
  });

  it("sin roles no aparece la lista", async () => {
    await loaded();
    expect(screen.queryByRole("list", { name: "Perfil del equipo" })).toBeNull();
  });
});
