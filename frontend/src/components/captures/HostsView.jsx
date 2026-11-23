import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

const W = 1100;
const H = 620;
const CX = W / 2;
const CY = H / 2;
const NODE_R = 18;
const RING_CAP = 24; // equipos por anillo

// Forma de cada nodo según su rol
const SHAPE_OF = { red_local: "circle", ipv6_local: "circle", multicast: "square", publica: "diamond", nube: "hexagon" };
function NodeShape({ kind }) {
  const r = NODE_R;
  if (kind === "square") return <rect x={-r} y={-r} width={2 * r} height={2 * r} rx="5" />;
  if (kind === "diamond") return <path d={`M0 ${-r - 3} L${r + 3} 0 L0 ${r + 3} L${-r - 3} 0 Z`} />;
  if (kind === "hexagon") return <path d={`M${-r / 2} ${-r} L${r / 2} ${-r} L${r + 2} 0 L${r / 2} ${r} L${-r / 2} ${r} L${-r - 2} 0 Z`} />;
  return <circle r={r} />;
}

const KIND_LABEL = { interna: "Interna", publica: "Pública", multicast: "Multicast" };

const place = (i, n, rx, ry, offset = 0) => {
  const angle = -Math.PI / 2 + offset + (2 * Math.PI * i) / n; // arranca arriba y sigue en sentido horario
  const cos = Math.cos(angle);
  return { x: CX + rx * cos, y: CY + ry * Math.sin(angle), cos, anchor: Math.abs(cos) < 0.2 ? "middle" : cos > 0 ? "start" : "end" };
};

// Disposición «telaraña»: tu red en el centro y el resto en anillos alrededor
export function layoutGraph(nodes) {
  const inner = nodes.filter((n) => n.kind === "interna");
  const outer = nodes.filter((n) => n.kind !== "interna");
  const pos = {};
  // Tu red: 1 equipo va al centro
  if (inner.length === 1) pos[inner[0].ip] = { x: CX, y: CY, cos: 0, anchor: "middle", ring: 0 };
  else {
    const tiers = [[10, 100, 70], [20, 175, 125], [Infinity, 260, 185]];
    let start = 0;
    tiers.forEach(([cap, rx, ry], t) => {
      const group = inner.slice(start, start + cap);
      start += group.length;
      const rxx = t === 0 ? Math.min(44 + group.length * 6, rx) : rx;
      const ryy = t === 0 ? Math.min(32 + group.length * 4, ry) : ry;
      group.forEach((n, i) => (pos[n.ip] = { ...place(i, group.length, rxx, ryy, t * 0.3), ring: 0 }));
    });
  }
  const first = outer.slice(0, RING_CAP);
  const second = outer.slice(RING_CAP);
  first.forEach((n, i) => (pos[n.ip] = { ...place(i, first.length, 310, 220), ring: 1 }));
  second.forEach((n, i) => (pos[n.ip] = { ...place(i, second.length, 380, 270, Math.PI / Math.max(second.length, 1)), ring: 2 }));
  return { pos, width: W, height: H, rings: second.length > 0 ? 2 : outer.length > 0 ? 1 : 0 };
}

// Qué se muestra como nombre de un equipo y de dónde sale
export function nodeLabel(n) {
  if (n.name) return { text: n.name, source: "captura" };
  if (n.owner) return { text: `${n.owner} · ${n.ip}`, source: "rango" };
  if (n.note) return { text: n.note.split(" (")[0], source: "especial" };
  return { text: n.label ?? n.ip, source: null };
}

const SOURCE_NOTE = {
  captura: "Nombre sacado de la propia captura (DNS o TLS)",
  rango: "Dueño del rango de IP según una tabla local: es una pista, no una prueba (la nube se alquila)",
  especial: "Dirección especial de la red",
};

// Dibujitos de 24×24 por tipo de equipo
const ICONS = {
  // computadora de escritorio: torre + pantalla
  red_local: <><rect x="2.5" y="6" width="6" height="14" rx="1" /><path d="M4 9.5h3M5.5 17h.01" /><rect x="10" y="4" width="12" height="9" rx="1" /><path d="M16 13v3.5M12.5 17.5h7" /></>,
  // notebook: otro equipo del mismo enlace (IPv6 de enlace local)
  ipv6_local: <><rect x="5" y="5" width="14" height="10" rx="1" /><path d="M2.5 19h19l-2-4h-15z" /></>,
  // antena: tráfico que va a un grupo o a todos
  multicast: <><circle cx="12" cy="12" r="2" /><path d="M7.5 7.5a6.4 6.4 0 0 0 0 9M16.5 7.5a6.4 6.4 0 0 1 0 9M4.5 4.5a10.6 10.6 0 0 0 0 15M19.5 4.5a10.6 10.6 0 0 1 0 15" /></>,
  // servidor de un proveedor conocido (nube)
  nube: <path d="M6.5 18h10a4.5 4.5 0 0 0 .6-8.9A6 6 0 0 0 5.6 10.6 3.8 3.8 0 0 0 6.5 18z" />,
  // servidor en internet
  publica: <><circle cx="12" cy="12" r="9" /><ellipse cx="12" cy="12" rx="4" ry="9" /><path d="M3 12h18" /></>,
};
export const iconOf = (n) => (n.owner && n.role === "publica" ? "nube" : Object.hasOwn(ICONS, n.role) ? n.role : "publica");

const LEGEND = [
  ["red_local", "equipo de tu red"],
  ["ipv6_local", "otro equipo del enlace (IPv6)"],
  ["multicast", "multicast / difusión"],
  ["nube", "proveedor conocido"],
  ["publica", "servidor en internet"],
];

const Icon = ({ name, x = 0, y = 0 }) => (
  <g className="gicon" transform={`translate(${x}, ${y})`} aria-hidden="true">{ICONS[name]}</g>
);

const short = (text, n = 30) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);

// «Equipos»: una fila por IP y un grafo de quién habla con quién
export default function HostsView({ refreshKey, onError, onFilterIp }) {
  const [hosts, setHosts] = useState(null);
  const [graph, setGraph] = useState(null);
  const [hover, setHover] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    Promise.all([api.hosts(ctl.signal), api.graph(ctl.signal)])
      .then(([h, g]) => {
        setHosts(h);
        setGraph(g);
      })
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  // El hover cambia a cada pasada del ratón
  const layout = useMemo(() => {
    if (!graph) return null;
    return { ...layoutGraph(graph.nodes), maxBytes: Math.max(...graph.edges.map((e) => e.bytes), 1) };
  }, [graph]);
  const neighbors = useMemo(() => {
    const set = new Set();
    if (!hover || !graph) return set;
    for (const e of graph.edges) {
      if (e.a === hover) set.add(e.b);
      else if (e.b === hover) set.add(e.a);
    }
    return set;
  }, [graph, hover]);

  if (!hosts || !graph || hosts.items.length === 0) return null;
  const { pos, rings, maxBytes } = layout;
  const linked = (ip) => neighbors.has(ip);
  const summary = `Grafo de ${graph.nodes.length} equipos y ${graph.edges.length} conversaciones entre ellos.`;

  return (
    <section className="card" aria-labelledby="hosts-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="hosts-title">Equipos</h2>
          <HelpTip topic="equipos" />
        </div>
        <span className="muted">{hosts.total.toLocaleString("es-AR")} IP distintas</span>
      </div>

      <div className="graph-wrap">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={summary} className="graph">
          <g className="web" aria-hidden="true">
            {rings >= 1 && <ellipse cx={CX} cy={CY} rx="310" ry="220" />}
            {rings >= 2 && <ellipse cx={CX} cy={CY} rx="380" ry="270" />}
          </g>
          {graph.edges.map((e) => {
            const a = pos[e.a];
            const b = pos[e.b];
            if (!a || !b) return null;
            const active = hover && (e.a === hover || e.b === hover);
            return (
              <line
                key={`${e.a}|${e.b}`}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                className={active ? "edge active" : "edge"}
                strokeWidth={1 + 5 * Math.sqrt(e.bytes / maxBytes)}
              >
                <title>{`${e.a} ↔ ${e.b} · ${e.sessions} sesión(es) · ${formatBytes(e.bytes)} · ${e.protocols.join(", ")}`}</title>
              </line>
            );
          })}
          {graph.nodes.map((n) => {
            const p = pos[n.ip];
            const flagged = n.alerts > 0 || n.ioc;
            const lab = nodeLabel(n);
            const dim = hover && hover !== n.ip && !linked(n.ip);
            return (
              <g
                key={n.ip}
                className={`gnode gnode-${n.kind}${flagged ? " flagged" : ""}${dim ? " dim" : ""}`}
                transform={`translate(${p.x}, ${p.y})`}
                tabIndex={0}
                role="button"
                aria-label={`${lab.text} (${n.ip}). Ver sus sesiones`}
                onMouseEnter={() => setHover(n.ip)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(n.ip)}
                onBlur={() => setHover(null)}
                onClick={() => onFilterIp?.(n.ip)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onFilterIp?.(n.ip)}
              >
                <NodeShape kind={SHAPE_OF[iconOf(n)] ?? SHAPE_OF[n.role] ?? "circle"} />
                <Icon name={iconOf(n)} x={-12} y={-12} />
                <text
                  x={p.anchor === "start" ? NODE_R + 8 : p.anchor === "end" ? -(NODE_R + 8) : 0}
                  y={p.anchor === "middle" ? (p.y < CY ? -(NODE_R + 8) : NODE_R + 17) : 4}
                  textAnchor={p.anchor}
                  className={lab.source === "rango" || lab.source === "especial" ? "gsoft" : undefined}
                >
                  {short(lab.text, p.anchor === "middle" ? 16 : 20)}
                  {flagged && <tspan className="gflag" dx="6">{n.ioc ? "IOC" : `! ${n.alerts}`}</tspan>}
                </text>
                <title>{[
                  n.ip,
                  lab.text !== n.ip && lab.text !== `${n.owner} · ${n.ip}` ? lab.text : null,
                  n.role_label ?? KIND_LABEL[n.kind] ?? n.kind,
                  lab.source ? SOURCE_NOTE[lab.source] : null,
                  `${n.sessions} sesión(es)`,
                  formatBytes(n.bytes),
                ].filter(Boolean).join(" · ")}</title>
              </g>
            );
          })}
        </svg>
        <ul className="graph-legend" aria-label="Qué significa cada dibujo">
          {LEGEND.map(([k, t]) => (
            <li key={k}>
              <svg viewBox="0 0 24 24" width="20" height="20" className="gicon" aria-hidden="true">{ICONS[k]}</svg> {t}
            </li>
          ))}
        </ul>
        <p className="muted graph-foot">
          Tu red está en el centro y el resto de los equipos, alrededor. El grosor de la línea es el tráfico. Hacé clic en un
          equipo para ver sus sesiones. Los nombres en gris claro son una pista por el dueño del rango de IP (no vienen de la
          captura); el nombre real aparece cuando la captura lo contiene.
          {graph.truncated ? " Se muestran solo los de más tráfico." : ""}
        </p>
      </div>

      <details className="hosts-table">
        <summary>Tabla de equipos ({Math.min(hosts.items.length, 50)} con más tráfico)</summary>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">IP</th>
                <th scope="col">Tipo</th>
                <th scope="col">Nombre</th>
                <th scope="col" className="num">Sesiones</th>
                <th scope="col" className="num">Con quién habla</th>
                <th scope="col" className="num">Bytes</th>
                <th scope="col">Protocolos</th>
                <th scope="col">Servicios que ofrece</th>
                <th scope="col" className="num">Alertas</th>
              </tr>
            </thead>
            <tbody>
              {hosts.items.map((h) => (
                <tr key={h.ip} className={h.ioc.length > 0 ? "row-ioc" : ""}>
                  <td className="mono">
                    <button type="button" className="link" onClick={() => onFilterIp?.(h.ip)}>{h.ip}</button>
                  </td>
                  <td>
                    {h.role_label || KIND_LABEL[h.kind] || h.kind}
                    {/* Perfil: roles inferidos de lo observado en la captura */}
                    {h.roles?.length > 0 && (
                      <ul className="host-roles" aria-label="Perfil del equipo">
                        {h.roles.map((r) => (
                          <li key={r} className="badge">{r}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="mono">
                    {h.name ?? (h.owner ? <span className="muted" title={SOURCE_NOTE.rango}>{h.owner}</span> : h.note ? <span className="muted">{h.note}</span> : <span className="muted">—</span>)}
                  </td>
                  <td className="num">{h.sessions.toLocaleString("es-AR")}</td>
                  <td className="num">{h.peers.toLocaleString("es-AR")}</td>
                  <td className="num">{formatBytes(h.bytes)}</td>
                  <td>{h.protocols.join(", ")}</td>
                  <td className="mono">
                    {h.services.length === 0 ? <span className="muted">—</span> : h.services.map((s) => `${s.protocol}/${s.port}`).join(" ")}
                  </td>
                  <td className="num">
                    {h.alerts > 0 ? `${h.alerts} (${h.alert_rules.join(", ")})` : <span className="muted">0</span>}
                    {h.ioc.length > 0 && <span className="badge sev-high" title={`Coincide con: ${h.ioc.join(", ")}`}>IOC</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
