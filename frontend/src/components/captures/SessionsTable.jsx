import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes, formatDuration, formatEndpoint } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

export const PAGE_SIZE = 25;

// Clase de color por protocolo
const KNOWN_PROTOCOLS = ["tcp", "udp", "icmp", "icmpv6"];
export function protoClass(protocol) {
  const slug = String(protocol ?? "").toLowerCase();
  return KNOWN_PROTOCOLS.includes(slug) ? slug : "other";
}

// Un color por nombre de proceso (paleta de 8): el mismo programa se reconoce de un vistazo
const PALETTE_SIZE = 8;
const processColors = new Map();
export function processColor(name) {
  const key = String(name ?? "");
  if (!processColors.has(key)) processColors.set(key, (processColors.size % PALETTE_SIZE) + 1);
  return processColors.get(key);
}

// Marcas del analista y coincidencias de IOC
function TriageMarks({ session }) {
  return (
    <>
      {session.reviewed && <span className="mark" title="Marcada como revisada">✓</span>}
      {session.note && <span className="mark" title={session.note}>nota</span>}
      {session.ioc?.length > 0 && (
        <span className="badge sev-high" title={`Coincide con: ${session.ioc.join(", ")}`}>IOC</span>
      )}
    </>
  );
}

// El nombre sale del sistema (puede contener cualquier cosa): se muestra solo como texto.
function ProcessCell({ process }) {
  if (!process) {
    return (
      <td className="muted" title="No se pudo identificar el proceso (por ejemplo, una conexión muy corta)">
        —
      </td>
    );
  }
  return (
    <td className="mono" title={`PID ${process.pid}`}>
      <span className={`dot proc-${processColor(process.name)}`} aria-hidden="true" />
      {process.name}
    </td>
  );
}

// `showProcess`
export default function SessionsTable({
  refreshKey, filters, onFilters, selectedId, onSelect, showProcess = false, triageVersion = 0,
}) {
  // Borrador del formulario: se aplica al enviar, no en cada tecla
  const [draft, setDraft] = useState(filters);
  // La página va atada a los filtros con los que se eligió
  const resetKey = JSON.stringify([filters, refreshKey]);
  const [pageState, setPageState] = useState({ key: resetKey, page: 0 });
  const page = pageState.key === resetKey ? pageState.page : 0;
  const setPage = (p) => setPageState({ key: resetKey, page: p });
  const [data, setData] = useState(null); // { total, items }
  const [failure, setFailure] = useState(null); // error del último pedido

  useEffect(() => setDraft(filters), [filters]);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .sessions({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE }, ctl.signal)
      .then((d) => {
        setFailure(null);
        setData(d);
      })
      .catch((e) => {
        if (e.name === "AbortError") return;
        // Un filtro inválido NO se muestra como "no hay sesiones"
        setFailure(e.message);
        setData(null);
      });
    return () => ctl.abort();
  }, [filters, page, refreshKey, triageVersion]);

  function submit(e) {
    e.preventDefault();
    onFilters({ protocol: draft.protocol.trim(), ip: draft.ip.trim(), port: draft.port.trim() });
  }

  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value });
  const showDirection = (data?.items ?? []).some((s) => s.direction); // la columna solo aparece si la API manda la dirección
  const showHost = (data?.items ?? []).some((s) => s.host); // la columna solo aparece si hay algún nombre conocido
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const active = Object.values(filters).some((v) => v !== "" && v != null);

  return (
    <section className="card" aria-labelledby="sessions-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="sessions-title">Sesiones</h2>
          <HelpTip topic="sesiones" />
        </div>
        <span className="muted" role="status">
          {failure ? "—" : data ? `${total.toLocaleString("es-AR")} ${active ? "coinciden" : "en total"}` : "Cargando…"}
        </span>
      </div>

      <form className="filters" onSubmit={submit}>
        <label>
          Protocolo
          <input value={draft.protocol} onChange={set("protocol")} placeholder="TCP, UDP…" list="protos" />
          <datalist id="protos">
            <option value="TCP" />
            <option value="UDP" />
            <option value="ICMP" />
            <option value="ICMPv6" />
          </datalist>
        </label>
        <label>
          IP
          <input value={draft.ip} onChange={set("ip")} placeholder="192.168.1.5" spellCheck={false} />
        </label>
        <label>
          Puerto
          <input
            value={draft.port}
            onChange={set("port")}
            placeholder="0–65535"
            inputMode="numeric"
            pattern="[0-9]*"
          />
        </label>
        <button type="submit">Filtrar</button>
        <button
          type="button"
          className="link"
          disabled={!active}
          onClick={() => onFilters({ protocol: "", ip: "", port: "" })}
        >
          Limpiar
        </button>
      </form>

      {failure ? (
        <p className="banner banner-error">No se pudo aplicar el filtro: {failure}</p>
      ) : data && data.items.length === 0 ? (
        <p className="empty">No hay sesiones con esos criterios.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col">Protocolo</th>
                <th scope="col">Origen</th>
                <th scope="col">Destino</th>
                {showDirection && (
                  <th scope="col" title="De quién a quién, respecto de tu red (cliente → servidor)">Dirección</th>
                )}
                {showHost && <th scope="col">Sitio</th>}
                {showProcess && <th scope="col">Proceso</th>}
                <th scope="col" className="num">Paquetes</th>
                <th scope="col" className="num">Bytes</th>
                <th scope="col" className="num">Duración</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map((s) => (
                <tr
                  key={s.id}
                  className={[s.id === selectedId && "selected", s.ioc?.length > 0 && "row-ioc", s.reviewed && "row-reviewed"]
                    .filter(Boolean)
                    .join(" ")}
                >
                  <td>
                    <button
                      type="button"
                      className="link"
                      onClick={() => onSelect(s)}
                      aria-label={`Ver paquetes de la sesión ${s.id}`}
                      aria-pressed={s.id === selectedId}
                    >
                      {s.id}
                    </button>
                    <TriageMarks session={s} />
                  </td>
                  <td>
                    <span className={`proto proto-${protoClass(s.protocol)}`}>{s.protocol}</span>
                  </td>
                  <td className="mono">{formatEndpoint(s.src_ip, s.src_port)}</td>
                  <td className="mono">{formatEndpoint(s.dst_ip, s.dst_port)}</td>
                  {showDirection && <td>{s.direction ?? "—"}</td>}
                  {showHost && (
                    <td className="mono" title="Nombre sacado de las respuestas DNS o del saludo TLS (SNI) de la captura">
                      {s.host ?? <span className="muted">—</span>}
                    </td>
                  )}
                  {showProcess && <ProcessCell process={s.process} />}
                  <td className="num">{s.packets.toLocaleString("es-AR")}</td>
                  <td className="num">{formatBytes(s.bytes)}</td>
                  <td className="num">{formatDuration(s.duration)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pages > 1 && (
        <nav className="pager" aria-label="Paginación de sesiones">
          <button type="button" onClick={() => setPage(page - 1)} disabled={page === 0}>
            Anterior
          </button>
          <span>
            Página {page + 1} de {pages}
          </span>
          <button type="button" onClick={() => setPage(page + 1)} disabled={page + 1 >= pages}>
            Siguiente
          </button>
        </nav>
      )}
    </section>
  );
}
