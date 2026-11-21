import { useState } from "react";
import { api } from "../../api/client.js";
import { formatDuration } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";
import { useAction } from "../../controllers/useAction.js";
import { useLoad } from "../../controllers/useLoad.js";

const when = (epoch) => (Number.isFinite(epoch) ? new Date(epoch * 1000).toLocaleTimeString("es-AR") : "—");
const LAYER_TEXT = {
  "red local": "No llegaba al router (red local o Wi-Fi)",
  internet: "El router respondía pero no había salida a Internet",
  dns: "Había Internet pero fallaba el DNS",
};

// Una barra por medición: la altura es la latencia; en rojo, las veces que algo falló.
function Spark({ samples }) {
  if (samples.length === 0) return null;
  const max = Math.max(...samples.map((s) => s.ms ?? 0), 50);
  return (
    <div className="bars spark" role="img" aria-label={`Últimas ${samples.length} mediciones`}>
      {samples.map((s, i) => (
        <i key={i} className={s.layer ? "bad" : ""} style={{ height: s.layer ? "100%" : `${Math.max(6, ((s.ms ?? 0) / max) * 100)}%` }} title={s.layer ? `Falla: ${s.layer}` : `${s.ms} ms`} />
      ))}
    </div>
  );
}

// «Monitoreo de cortes»: mide en segundo plano y anota cuándo y por qué se cortó la conexión.
export default function MonitorView({ active }) {
  const [interval, setIntervalSec] = useState(2);
  const { data, error, reload } = useLoad((s) => api.monitorStatus(s), { every: 2000, active });
  const act = useAction((fn) => fn());
  const status = data;

  async function call(fn) {
    await act.run(fn);
    reload();
  }

  return (
    <section className="card" aria-labelledby="mon-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="mon-title">Monitoreo de cortes</h2>
          <HelpTip topic="soporte_monitoreo" />
        </div>
        <span className="muted">{status?.running ? "midiendo…" : "detenido"}</span>
      </div>
      <div className="filters">
        {!status?.running ? (
          <>
            <label>
              Medir cada
              <select value={interval} onChange={(e) => setIntervalSec(Number(e.target.value))}>
                {[1, 2, 5, 10].map((n) => <option key={n} value={n}>{n} s</option>)}
              </select>
            </label>
            <button type="button" onClick={() => call(() => api.monitorStart(interval))}>Empezar a monitorear</button>
          </>
        ) : (
          <button type="button" onClick={() => call(() => api.monitorStop())}>Detener</button>
        )}
        <button type="button" onClick={() => call(() => api.monitorClear())} disabled={!status || status.total === 0}>Borrar registro</button>
        <span className="muted">Solo mide mientras Tracewell está abierto; lo registrado se pierde al cerrarlo. Hace un ping a tu router y abre conexiones cortas a 1.1.1.1 y a sitios conocidos.</span>
      </div>
      {(error || act.error) && <p className="banner banner-error" role="alert">{error ?? act.error}</p>}
      {status && status.total > 0 && (
        <div className="pad">
          <div className={`verdict ${status.current === "ok" ? "verdict-ok" : "verdict-bad"}`} role="status">
            <strong>{status.current === "ok" ? "Ahora: todo funciona" : status.current === "sin datos" ? "Esperando la primera medición…" : `Ahora: falla (${status.current})`}</strong>
          </div>
          <dl className="facts">
            <div><dt>Disponibilidad</dt><dd>{status.availability_pct} % de {status.total} mediciones</dd></div>
            <div><dt>Cortes registrados</dt><dd>{status.outage_count} ({formatDuration(status.downtime_seconds)} en total)</dd></div>
            <div><dt>Latencia a Internet</dt><dd>{status.latency.last != null ? `${status.latency.last} ms (promedio ${status.latency.avg ?? "—"}, máximo ${status.latency.max ?? "—"})` : "—"}</dd></div>
            {status.wifi?.signal != null && <div><dt>Señal Wi-Fi</dt><dd>{status.wifi.signal} % ({status.wifi.ssid})</dd></div>}
            <div><dt>Router medido</dt><dd className="mono">{status.gateway ?? "no se encontró"}</dd></div>
          </dl>
          <Spark samples={status.samples} />
          <h3>Cronología de cortes</h3>
          {status.outages.length === 0 ? (
            <p className="muted">Sin cortes por ahora.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th scope="col">Empezó</th><th scope="col">Duró</th><th scope="col">Qué falló</th><th scope="col">Señal Wi-Fi al empezar</th></tr>
                </thead>
                <tbody>
                  {status.outages.map((o) => (
                    <tr key={o.start}>
                      <td className="mono">{when(o.start)}</td>
                      <td>{formatDuration(o.duration)}{o.ongoing ? " (en curso)" : ""}</td>
                      <td>{LAYER_TEXT[o.layer] ?? o.layer}</td>
                      <td>{o.signal != null ? `${o.signal} %` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {status && status.total === 0 && !status.running && <p className="muted pad">Apretá «Empezar a monitorear» y dejá Tracewell abierto mientras trabajás.</p>}
    </section>
  );
}
