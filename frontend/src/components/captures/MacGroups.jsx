import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";

// «Equipos por MAC»: agrupa las IP de la red local que comparten la misma dirección física.
// Varias IP con una MAC suelen ser IPv4 + IPv6 del mismo equipo, o un router/NAT que reenvía otras redes.
// Es una pista, no una prueba. Todo es texto de la captura: nunca HTML.
export default function MacGroups({ refreshKey, onError, onFilterIp }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .hostsByMac(ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  if (!data || data.items.length === 0) return null;
  const shared = data.items.filter((g) => g.shared).length;

  return (
    <section className="card" aria-labelledby="mac-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="mac-title">Equipos por MAC</h2>
        </div>
        <span className="muted">
          {data.total} MAC · {shared} con varias IP
        </span>
      </div>
      <p className="muted">
        Solo equipos de tu red local: la MAC de un destino en internet es la de tu router, así que no se muestra.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">MAC</th>
              <th scope="col">IP</th>
              <th scope="col" className="num">Sesiones</th>
              <th scope="col" className="num">Bytes</th>
              <th scope="col">Pista</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((g) => (
              <tr key={g.mac} className={g.shared ? "row-flag" : undefined}>
                <td className="mono">{g.mac}</td>
                <td className="mono">
                  {g.ips.map((ip) => (
                    <button key={ip} type="button" className="link" onClick={() => onFilterIp?.(ip)} title="Ver las sesiones de este equipo">
                      {ip}
                    </button>
                  ))}
                </td>
                <td className="num">{g.sessions.toLocaleString("es-AR")}</td>
                <td className="num">{formatBytes(g.bytes)}</td>
                <td>{g.hint || <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
