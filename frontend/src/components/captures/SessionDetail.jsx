import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes, formatEndpoint, formatTime } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";
import CopyFilterButton from "./CopyFilterButton.jsx";
import ExplainView from "./ExplainView.jsx";
import SessionHttp from "./SessionHttp.jsx";
import TlsView from "./TlsView.jsx";
import StreamView from "./StreamView.jsx";

const PAGE = 50;

// Resalta offset y panel ASCII solo con spans de texto (nunca HTML). Las líneas
// que no tienen el formato esperado se muestran tal cual; el texto total no cambia.
const HEX_LINE = /^([0-9a-f]{8})( {2})(.*?)( {2})(\|.*\|)$/;

const inRange = (n, hl) => hl != null && n >= hl.start && n < hl.end;

// Cada byte hexadecimal va en su propio <span> para poder resaltar un campo; el texto total no cambia.
function HexBytes({ text, base, highlight }) {
  let n = -1;
  return text.split(/([0-9a-f]{2})/).map((part, k) => {
    if (k % 2 === 0) return part; // los separadores (espacios)
    n += 1;
    return (
      <span key={k} className={inRange(base + n, highlight) ? "hex-hl" : undefined}>
        {part}
      </span>
    );
  });
}

function AsciiCells({ text, base, highlight }) {
  const chars = Array.from(text.slice(1, -1)); // sin las barras | de los extremos
  return (
    <>
      |
      {chars.map((c, j) => (
        <span key={j} className={inRange(base + j, highlight) ? "hex-hl" : undefined}>
          {c}
        </span>
      ))}
      |
    </>
  );
}

function HexLines({ text, highlight = null }) {
  return text.split("\n").map((line, i, all) => {
    const m = HEX_LINE.exec(line);
    const nl = i < all.length - 1 ? "\n" : "";
    if (!m) return line + nl;
    const base = parseInt(m[1], 16);
    return (
      <span key={i}>
        <span className="hex-off">{m[1]}</span>
        {m[2]}
        <span className="hex-bytes">
          <HexBytes text={m[3]} base={base} highlight={highlight} />
        </span>
        {m[4]}
        <span className="hex-ascii">
          <AsciiCells text={m[5]} base={base} highlight={highlight} />
        </span>
        {nl}
      </span>
    );
  });
}

// Árbol de capas (Ethernet, IP, TCP...). Pasar el mouse o dar foco a un campo resalta sus bytes en el
// hex dump; un clic lo deja fijo (para teclado y pantallas táctiles). Todo es texto: nunca HTML.
function PacketLayers({ layers, onHover, onPin, pinnedKey }) {
  return (
    <div className="layers">
      <h3>
        Capas <HelpTip topic="capas" />
      </h3>
      {layers.map((L) => (
        <details key={`${L.name}-${L.start}`} open>
          <summary
            onMouseEnter={() => onHover({ start: L.start, end: L.end })}
            onMouseLeave={() => onHover(null)}
          >
            {L.name} <span className="muted">· bytes {L.start}–{L.end}</span>
          </summary>
          {L.note && <p className="banner banner-warn" role="note">{L.note}</p>}
          <ul className="fields">
            {L.fields.map((f) => {
              const key = `${L.name}-${f.start}-${f.label}`;
              return (
                <li key={key}>
                  <button
                    type="button"
                    className="field"
                    aria-pressed={pinnedKey === key}
                    onMouseEnter={() => onHover({ start: f.start, end: f.end })}
                    onMouseLeave={() => onHover(null)}
                    onFocus={() => onHover({ start: f.start, end: f.end })}
                    onBlur={() => onHover(null)}
                    onClick={() => onPin(pinnedKey === key ? null : key, { start: f.start, end: f.end })}
                  >
                    <span className="field-label">{f.label}</span>
                    <span className="field-value mono">{f.value}</span>
                    {f.hint && <span className="field-hint muted">{f.hint}</span>}
                  </button>
                </li>
              );
            })}
          </ul>
        </details>
      ))}
    </div>
  );
}

function PacketView({ index, onError }) {
  const [d, setD] = useState(null);
  const [hover, setHover] = useState(null); // rango de bytes bajo el mouse o el foco
  const [pinned, setPinned] = useState({ key: null, range: null }); // rango fijado con un clic

  useEffect(() => {
    setD(null);
    setHover(null);
    setPinned({ key: null, range: null });
    const ctl = new AbortController();
    api
      .packet(index, ctl.signal)
      .then(setD)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [index, onError]);

  if (!d) return <p className="empty">Cargando paquete…</p>;
  const e = d.endpoints;
  return (
    <div className="packet">
      <h3>
        Paquete {d.index} <HelpTip topic="hexdump" />
      </h3>
      <div className="packet-info">
        <p className="muted">
          {formatTime(d.ts)} · {d.caplen} B capturados
          {d.origlen != null ? ` de ${d.origlen} B` : ""}
        </p>
        {e && (
          <p className="mono">
            {e.protocol} {formatEndpoint(e.src_ip, e.src_port)} → {formatEndpoint(e.dst_ip, e.dst_port)}
          </p>
        )}
      </div>
      {d.snaplen_limited && (
        <p className="banner banner-warn" role="note">
          Paquete recortado por <em>snaplen</em>: el contenido está incompleto, y la ausencia de un texto
          en él no prueba que no estuviera en la red.
        </p>
      )}
      {/* Los bytes vienen del tráfico: se muestran como texto, nunca como HTML. */}
      <pre className="hexdump mono" aria-label="Volcado hexadecimal">
        <HexLines text={d.hexdump || "(sin datos)"} highlight={hover ?? pinned.range} />
      </pre>
      {d.layers?.length > 0 && (
        <PacketLayers
          layers={d.layers}
          onHover={setHover}
          onPin={(key, range) => setPinned({ key, range: key ? range : null })}
          pinnedKey={pinned.key}
        />
      )}
    </div>
  );
}

// Nota del analista y marca "revisada". El texto lo escribe una persona: se guarda y se muestra como texto.
function NoteForm({ session, onNoteSaved, onError }) {
  const [note, setNote] = useState(session.note ?? "");
  const [reviewed, setReviewed] = useState(Boolean(session.reviewed));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  // Solo al cambiar de sesión: depender también de note/reviewed borraría el aviso "Guardada"
  // justo después de guardar, porque guardar actualiza esos mismos valores.
  useEffect(() => {
    setNote(session.note ?? "");
    setReviewed(Boolean(session.reviewed));
    setSaved(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id]);

  async function save(e) {
    e.preventDefault();
    setSaving(true);
    setSaved(false);
    try {
      const r = await api.saveNote(session.id, { note, reviewed });
      const { note: _n, reviewed: _r, ...rest } = session;
      // Sin nota ni marca el servidor la borra: la sesión vuelve a su forma sin anotaciones.
      onNoteSaved?.(r.note || r.reviewed ? { ...rest, note: r.note || undefined, reviewed: r.reviewed || undefined } : rest);
      setSaved(true);
    } catch (err) {
      onError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="note-form" onSubmit={save}>
      <label htmlFor="session-note">Nota del analista</label>
      <textarea
        id="session-note"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        maxLength={2000}
        rows={3}
        placeholder="Ej.: es el keep-alive de una app conocida, legítimo"
      />
      <label className="inline">
        <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} />
        Marcar como revisada
      </label>
      <div className="note-actions">
        <button type="submit" disabled={saving}>Guardar nota</button>
        {saved && <span role="status" className="muted">Guardada</span>}
      </div>
    </form>
  );
}

export default function SessionDetail({ session, onClose, onError, onNoteSaved }) {
  const [items, setItems] = useState([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [picked, setPicked] = useState(null);

  async function load(offset, replace) {
    setLoading(true);
    try {
      const r = await api.sessionPackets(session.id, { limit: PAGE, offset });
      setItems((prev) => (replace ? r.items : [...prev, ...r.items]));
      setMore(r.has_more);
      if (replace && r.items.length) setPicked(r.items[0].index);
    } catch (e) {
      onError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setItems([]);
    setPicked(null);
    load(0, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id]);

  return (
    <aside className="card detail" aria-labelledby="detail-title">
      <div className="card-head">
        <h2 id="detail-title">Sesión {session.id}</h2>
        <button type="button" className="link" onClick={onClose}>
          Cerrar
        </button>
      </div>
      <div className="detail-meta">
        <p className="mono">
          {session.protocol} {formatEndpoint(session.src_ip, session.src_port)} →{" "}
          {formatEndpoint(session.dst_ip, session.dst_port)}
        </p>
        <p className="muted">
          {session.packets} paquetes · {formatBytes(session.bytes)}
        </p>
        {session.direction && (
          <p>
            Dirección: <strong>{session.direction}</strong>
          </p>
        )}
        {session.host && (
          <p>
            Sitio: <strong className="mono">{session.host}</strong>
          </p>
        )}
        {/* La clave `process` solo existe en una captura en vivo: sin ella no se muestra nada. */}
        {"process" in session && (
          <p>
            Proceso:{" "}
            {session.process ? (
              <>
                <strong className="mono">{session.process.name}</strong>{" "}
                <span className="muted">(PID {session.process.pid})</span>
              </>
            ) : (
              <span className="muted">no identificado</span>
            )}
          </p>
        )}
        {session.ioc?.length > 0 && (
          <p className="banner banner-warn" role="note">
            Coincide con un indicador de compromiso: <span className="mono">{session.ioc.join(", ")}</span>
          </p>
        )}
      </div>
      <p className="detail-actions-row">
        {/* Solo los paquetes de esta sesión, como un .pcap aparte. */}
        <a className="button" href={api.sessionPcapUrl(session.id)} download={`tracewell-sesion-${session.id}.pcap`}>
          Descargar .pcap de esta sesión
        </a>
        <HelpTip topic="pcap" />
        {/* Mismo tráfico en Wireshark: el filtro lo arma el servidor al pedirlo. */}
        <CopyFilterButton load={() => api.explain(session.id).then((r) => r.wireshark_filter)} onError={onError} />
      </p>
      <NoteForm session={session} onNoteSaved={onNoteSaved} onError={onError} />
      <ExplainView session={session} onError={onError} />
      <TlsView session={session} onError={onError} />
      <SessionHttp session={session} onError={onError} />
      <StreamView session={session} onError={onError} />

      <h3>Paquetes</h3>
      <ul className="packet-list">
        {items.map((p) => (
          <li key={p.index}>
            <button
              type="button"
              className={p.index === picked ? "selected" : ""}
              onClick={() => setPicked(p.index)}
              aria-pressed={p.index === picked}
            >
              <span>#{p.index}</span>
              <span className="muted">{formatTime(p.ts)}</span>
              <span className="num">{p.caplen} B</span>
              {p.snaplen_limited && <span className="badge sev-medium">recortado</span>}
            </button>
          </li>
        ))}
      </ul>
      {loading && <p className="empty">Cargando…</p>}
      {more && !loading && (
        <div className="detail-actions">
          <button type="button" onClick={() => load(items.length, false)}>
            Cargar más
          </button>
        </div>
      )}

      {picked !== null && <PacketView index={picked} onError={onError} />}
    </aside>
  );
}
