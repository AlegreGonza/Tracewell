import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatEndpoint, formatTime, severityLabel } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";
import CopyFilterButton from "./CopyFilterButton.jsx";

const SEV_LEVEL = { low: 1, medium: 2, high: 3, critical: 4 };

// `onViewSessions(alerta)`: salta a las sesiones de la IP de origen de la alerta.
export default function AlertsTable({ refreshKey, onError, onViewSessions }) {
  const [alerts, setAlerts] = useState(null);
  const [severity, setSeverity] = useState("");
  const [open, setOpen] = useState(null); // índice de la alerta expandida

  useEffect(() => {
    const ctl = new AbortController();
    api
      .alerts(severity || undefined, ctl.signal)
      .then((a) => {
        setAlerts(a);
        setOpen(null);
      })
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, severity, onError]);

  return (
    <section className="card" aria-labelledby="alerts-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="alerts-title">Alertas</h2>
          <HelpTip topic="alertas" />
        </div>
        <label className="inline">
          Severidad
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Todas</option>
            <option value="critical">Crítica</option>
            <option value="high">Alta</option>
            <option value="medium">Media</option>
            <option value="low">Baja</option>
          </select>
        </label>
      </div>
      {alerts === null ? (
        <p className="empty">Cargando…</p>
      ) : alerts.length === 0 ? (
        <p className="empty">No hay alertas{severity ? " con esa severidad" : ""}.</p>
      ) : (
        <ul className="alerts">
          {alerts.map((a, i) => (
            <li key={`${a.rule_id}-${i}`} className={`sev-${a.severity}`}>
              <button
                type="button"
                className="alert-row"
                onClick={() => setOpen(open === i ? null : i)}
                aria-expanded={open === i}
              >
                {/* Texto + color: la severidad nunca depende solo del color. */}
                <span className={`badge sev-${a.severity}`}>
                  <span className="sev-meter" aria-hidden="true">
                    {[1, 2, 3, 4].map((n) => (
                      <i key={n} className={n <= (SEV_LEVEL[a.severity] ?? 1) ? "on" : ""} />
                    ))}
                  </span>
                  {severityLabel(a.severity)}
                </span>
                <span className="alert-name">{a.name}</span>
                <span className="muted mono">
                  {formatEndpoint(a.src_ip)} → {formatEndpoint(a.dst_ip)}
                </span>
                <span className="alert-time">{formatTime(a.first_ts)}</span>
              </button>
              {open === i && (
                <div className="alert-detail">
                  <p>{a.description}</p>
                  <p>
                    <strong>MITRE ATT&amp;CK:</strong>{" "}
                    <a
                      href={`https://attack.mitre.org/techniques/${a.mitre_technique.replace(".", "/")}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {a.mitre_technique}
                    </a>{" "}
                    — {a.mitre_name} ({a.mitre_tactic})
                  </p>
                  <h3>Evidencia</h3>
                  {/* Texto plano dentro de <pre>: la evidencia viene de tráfico
                      que puede ser hostil, así que nunca se interpreta como HTML. */}
                  <pre className="mono">{JSON.stringify(a.evidence, null, 2)}</pre>
                  {a.wireshark_filter && (
                    <p className="alert-actions">
                      <CopyFilterButton filter={a.wireshark_filter} onError={onError} />
                    </p>
                  )}
                  {onViewSessions && (
                    <p className="alert-actions">
                      <button type="button" onClick={() => onViewSessions(a)}>
                        Ver las sesiones de {a.src_ip}
                      </button>
                      {/* Los paquetes de esa IP como un .pcap aparte (para Wireshark o un ticket). */}
                      <a className="button" href={api.filteredPcapUrl({ ip: a.src_ip })} download>
                        Descargar .pcap de {a.src_ip}
                      </a>
                    </p>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
