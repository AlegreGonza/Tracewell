import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";
import { httpNotes } from "./SessionHttp.jsx";

// «HTTP» de toda la captura
export default function HttpView({ refreshKey, onError, onFilterIp }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .httpOverview(ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  if (!data || data.items.length === 0) return null;
  const alarming = data.items.filter((ex) => httpNotes(ex).some((n) => n.includes("contraseña") || n.includes("Autenticación"))).length;
  const files = data.items.filter((ex) => ex.file).length;

  return (
    <section className="card" aria-labelledby="httpall-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="httpall-title">HTTP sin cifrar</h2>
          <HelpTip topic="http" />
        </div>
        <span className="muted">{data.items.length} petición(es) · {files} archivo(s) · {alarming} con credenciales</span>
      </div>
      {data.capped && <p className="banner banner-warn" role="note">Se muestran solo las primeras: la captura tiene más HTTP del que se lee de una vez.</p>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Sesión</th>
              <th scope="col">Pedido</th>
              <th scope="col" className="num">Estado</th>
              <th scope="col">Tipo</th>
              <th scope="col" className="num">Tamaño</th>
              <th scope="col">Notas</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((ex) => (
              <tr key={`${ex.session_id}-${ex.index}`}>
                <td className="mono">
                  #{ex.session_id}{" "}
                  <button type="button" className="link" onClick={() => onFilterIp?.(ex.src_ip ?? ex.src.slice(0, ex.src.lastIndexOf(":")))} title="Ver las sesiones de este origen">
                    {ex.src}
                  </button>
                </td>
                <td className="mono">
                  <strong>{ex.method}</strong> {ex.host ?? ex.dst}{ex.target}
                </td>
                <td className="num mono">{ex.status ?? "—"}</td>
                <td className="mono">{ex.response_type ?? "—"}</td>
                <td className="num">{formatBytes(ex.response_bytes)}</td>
                <td>
                  {httpNotes(ex).map((n) => (
                    <div key={n} className="note-chip">{n}</div>
                  ))}
                  {ex.file && (
                    <div className={ex.file.risky ? "note-chip risky" : "note-chip"}>
                      Archivo {ex.file.name}: {ex.file.kind} · SHA-256 {ex.file.sha256.slice(0, 16)}…
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
