import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes, formatTime } from "../../lib/format.js";

const SERVICES = ["SSH", "Telnet", "SMB", "RDP", "WinRM", "VNC"];
const n = (v) => v.toLocaleString("es-AR");

// «Acceso remoto»: quién se conecta por SSH, Telnet, SMB, RDP, WinRM o VNC, agrupado por servicio.
// Las señales (RST, reintentos) son pistas: un RST puede ser un puerto cerrado o un corte normal.
// Todo es texto que viene de la captura: React lo escapa, nunca se usa HTML.
function ServiceGroup({ group, onFilterIp }) {
  return (
    <section className="remote-group" aria-labelledby={`remote-${group.service}`}>
      <h3 id={`remote-${group.service}`}>
        {group.service} <span className="muted">(puerto {group.ports.join(", ")})</span>
      </h3>
      <p className="muted">
        {n(group.sessions)} sesiones · {n(group.clients)} cliente(s) · {n(group.servers)} servidor(es) · {n(group.with_rst)} con RST ·{" "}
        {n(group.retries)} reintento(s) · {formatBytes(group.bytes)}
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Cliente</th>
              <th scope="col">Servidor</th>
              <th scope="col">Dirección</th>
              <th scope="col">Inicio</th>
              <th scope="col" className="num">Paquetes</th>
              <th scope="col" className="num">Bytes</th>
              <th scope="col" className="num">RST</th>
              <th scope="col" className="num">Reintentos</th>
              <th scope="col">Señales</th>
            </tr>
          </thead>
          <tbody>
            {group.items.map((i) => (
              <tr key={i.id} className={i.rst_packets || i.syn_retries ? "row-flag" : undefined}>
                <td className="mono">
                  <button type="button" className="link" onClick={() => onFilterIp?.(i.client_ip)} title="Ver las sesiones de este equipo">
                    {i.client_ip}
                  </button>
                </td>
                <td className="mono">{i.server_ip}:{i.port}</td>
                <td>{i.direction}</td>
                <td>{formatTime(i.first_ts)}</td>
                <td className="num">{n(i.packets)}</td>
                <td className="num">{formatBytes(i.bytes)}</td>
                <td className="num">{i.rst_packets}</td>
                <td className="num">{i.syn_retries}</td>
                <td>{i.signals.length ? i.signals.join(" · ") : <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {group.truncated && <p className="banner banner-warn" role="note">Se muestran las primeras {group.items.length} sesiones; el resumen cuenta todas.</p>}
    </section>
  );
}

export default function RemoteAccessView({ refreshKey, onError, onFilterIp }) {
  const [service, setService] = useState("");
  const [data, setData] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .remoteAccess(service || undefined, ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, service, onError]);

  return (
    <section className="card" aria-labelledby="remote-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="remote-title">Acceso remoto</h2>
        </div>
        <label className="inline">
          Servicio
          <select value={service} onChange={(e) => setService(e.target.value)}>
            <option value="">Todos</option>
            {SERVICES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
      </div>
      <p className="muted">
        Conexiones a SSH (22), Telnet (23), SMB (445), RDP (3389), WinRM (5985/5986) y VNC (5900). Un RST o varios SYN seguidos pueden indicar
        un acceso rechazado o reintentos (por ejemplo, fuerza bruta), pero también un puerto cerrado o pérdida de paquetes.
      </p>
      {data === null ? (
        <p className="empty">Cargando…</p>
      ) : data.total === 0 ? (
        <p className="empty">No hay conexiones de acceso remoto{service ? ` por ${service}` : ""} en esta captura.</p>
      ) : (
        data.services.map((g) => <ServiceGroup key={g.service} group={g} onFilterIp={onFilterIp} />)
      )}
    </section>
  );
}
