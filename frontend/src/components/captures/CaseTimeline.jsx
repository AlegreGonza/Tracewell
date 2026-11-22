import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatTime, severityLabel } from "../../lib/format.js";

// Etiqueta en texto (nunca solo color) de cada tipo de hecho.
const KIND_LABEL = { alerta: "Alerta", dns: "DNS", ioc: "IOC", sesion: "Sesión" };

// «Cronología del caso»: alertas, DNS sospechoso, sesiones marcadas e IOC juntos, en orden de tiempo.
// Es distinta del gráfico de tráfico por intervalo. Todo es texto que viene de la captura: nunca HTML.
export default function CaseTimeline({ refreshKey, triageVersion = 0, onError, onFilterIp }) {
  const [host, setHost] = useState("");
  const [applied, setApplied] = useState("");
  const [data, setData] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .caseTimeline(applied || undefined, ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, triageVersion, applied, onError]);

  return (
    <section className="card" aria-labelledby="case-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="case-title">Cronología del caso</h2>
        </div>
        {data && (
          <span className="muted">
            {data.total.toLocaleString("es-AR")} hechos{data.host ? ` de ${data.host}` : ""} · horas en UTC
          </span>
        )}
      </div>
      <p className="muted">
        Alertas, consultas DNS sospechosas, sesiones que marcaste y coincidencias con IOC, en el orden en que ocurrieron. Sirve para contar el
        caso de principio a fin.
      </p>
      <form className="dns-search" onSubmit={(e) => { e.preventDefault(); setApplied(host.trim()); }}>
        <label className="sr-only" htmlFor="case-host">Equipo (IP)</label>
        <input id="case-host" type="search" value={host} onChange={(e) => setHost(e.target.value)} placeholder="Limitar a un equipo (IP)" autoComplete="off" />
        <button type="submit">Limitar al equipo</button>
        {applied && (
          <button type="button" onClick={() => { setHost(""); setApplied(""); }}>Quitar filtro</button>
        )}
      </form>
      {data === null ? (
        <p className="empty">Cargando…</p>
      ) : data.items.length === 0 ? (
        <p className="empty">No hay hechos para mostrar{applied ? " de ese equipo" : ""}.</p>
      ) : (
        <>
          <ol className="case-timeline" aria-label="Hechos del caso en orden cronológico">
            {data.items.map((e, i) => (
              <li key={`${e.kind}-${e.ts}-${i}`} className={`case-${e.kind}${e.severity ? ` sev-${e.severity}` : ""}`}>
                <time className="mono">{formatTime(e.ts)}</time>
                <span className="badge">{KIND_LABEL[e.kind] ?? e.kind}</span>
                <span className="case-body">
                  <strong>{e.title}</strong>
                  {e.severity && <span className="muted"> · {severityLabel(e.severity)}</span>}
                  <span className="muted case-detail">{e.detail}</span>
                </span>
                {onFilterIp && e.ips?.length > 0 && (
                  <button type="button" className="link" onClick={() => onFilterIp(e.ips[0])} title="Ver las sesiones de este equipo">
                    Ver sesiones de {e.ips[0]}
                  </button>
                )}
              </li>
            ))}
          </ol>
          {data.truncated && (
            <p className="banner banner-warn" role="note">
              Hay más hechos: se muestran los primeros {data.items.length}. Filtrá por un equipo para ver el resto.
            </p>
          )}
        </>
      )}
    </section>
  );
}
