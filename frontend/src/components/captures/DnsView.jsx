import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatTime } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

const n = (v) => v.toLocaleString("es-AR");

// «DNS»: los nombres que se consultaron, cuántas veces, qué respondieron y qué salió mal.
// Se ve de un vistazo a qué se conectaron los equipos y qué nombres no existen.
export default function DnsView({ refreshKey, onError }) {
  const [query, setQuery] = useState("");
  const [applied, setApplied] = useState("");
  const [data, setData] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .dns(applied || undefined, ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, applied, onError]);

  if (!data || (data.items.length === 0 && !applied && data.summary.names === 0)) return null;
  const { summary } = data;

  return (
    <section className="card" aria-labelledby="dns-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="dns-title">DNS</h2>
          <HelpTip topic="dns" />
        </div>
        <span className="muted">
          {n(summary.names)} nombres · {n(summary.queries)} consultas · {n(summary.nxdomain)} NXDOMAIN · {n(summary.flagged)} con pistas
        </span>
      </div>
      <details className="dns-details">
        <summary>Ver la tabla de DNS</summary>
        <form className="dns-search" onSubmit={(e) => { e.preventDefault(); setApplied(query.trim()); }}>
          <label className="sr-only" htmlFor="dns-q">Buscar un nombre</label>
          <input id="dns-q" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Buscar un nombre (por ejemplo: google)" autoComplete="off" />
          <button type="submit">Buscar</button>
        </form>
        {data.items.length === 0 ? (
          <p className="empty">Ningún nombre coincide.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Nombre</th>
                  <th scope="col">Tipo</th>
                  <th scope="col" className="num">Consultas</th>
                  <th scope="col" className="num">Respuestas</th>
                  <th scope="col">Resultado</th>
                  <th scope="col">Respondió</th>
                  <th scope="col" className="num">TTL mín.</th>
                  <th scope="col">Pistas</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr key={`${r.name}|${r.qtype}`} title={`Visto de ${formatTime(r.first_ts)} a ${formatTime(r.last_ts)}`}>
                    <td className="mono">{r.name}</td>
                    <td className="mono">{r.qtype}</td>
                    <td className="num">{n(r.queries)}</td>
                    <td className="num">{n(r.responses)}</td>
                    <td className="mono">
                      {Object.entries(r.rcodes).map(([code, count]) => `${code}×${count}`).join(" ") || <span className="muted">—</span>}
                    </td>
                    <td className="mono">{r.answers.join(", ") || <span className="muted">—</span>}</td>
                    <td className="num">{r.min_ttl ?? "—"}</td>
                    <td>
                      {r.hints.map((h) => (
                        <div key={h} className="note-chip">{h}</div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </details>
    </section>
  );
}
