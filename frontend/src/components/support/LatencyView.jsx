import { useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import { useAction } from "../../controllers/useAction.js";

const ms = (v) => (v == null ? "—" : `${v} ms`);

// Veredicto simple de la latencia hacia un servidor público (umbrales orientativos).
export function latencyVerdict(avg) {
  if (avg == null) return "No se pudo medir.";
  if (avg < 30) return "Excelente: se nota instantáneo.";
  if (avg < 80) return "Buena para casi todo.";
  if (avg < 150) return "Aceptable, pero las videollamadas y los juegos pueden sentirse lentos.";
  return "Alta: todo va a sentirse lento.";
}

// Barras con cada medición (la altura es el tiempo; las fallidas no aparecen).
function Bars({ times }) {
  const max = Math.max(...times, 1);
  return (
    <div className="bars" role="img" aria-label={`${times.length} mediciones, entre ${Math.min(...times)} y ${Math.max(...times)} ms`}>
      {times.map((t, i) => (
        <i key={i} style={{ height: `${Math.max(6, (t / max) * 100)}%` }} title={`${t} ms`} />
      ))}
    </div>
  );
}

// «Latencia»: cuánto tarda en ir y volver un mensaje, hacia Internet y hacia tu router.
export default function LatencyView() {
  const [host, setHost] = useState("1.1.1.1");
  const test = useAction((params, s) => api.supportLatency(params, s));
  const r = test.result;

  return (
    <section className="card" aria-labelledby="lat-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="lat-title">Latencia</h2>
          <HelpTip topic="soporte_latencia" />
        </div>
      </div>
      <form
        className="filters"
        onSubmit={(e) => {
          e.preventDefault();
          test.run({ host, port: 443, samples: 8 });
        }}
      >
        <label>
          Servidor a medir (puerto 443)
          <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="1.1.1.1" />
        </label>
        <button type="submit" disabled={test.loading}>{test.loading ? "Midiendo…" : "Medir"}</button>
        <span className="muted">Abre 8 conexiones cortas a ese servidor y hace un ping a tu router. Tarda unos segundos.</span>
      </form>
      {test.error && <p className="banner banner-error" role="alert">{test.error}</p>}
      {r && (
        <div className="pad">
          <p><strong>{latencyVerdict(r.avg)}</strong></p>
          <dl className="facts">
            <div><dt>Promedio</dt><dd>{ms(r.avg)}</dd></div>
            <div><dt>Mejor / peor</dt><dd>{ms(r.min)} / {ms(r.max)}</dd></div>
            <div><dt>Variación (jitter)</dt><dd>{ms(r.jitter)}</dd></div>
            <div><dt>Fallidas</dt><dd>{r.failed} de {r.samples}</dd></div>
            <div><dt>Tu router ({r.router?.host ?? "?"})</dt><dd>{r.router ? `${ms(r.router.avg)} · ${r.router.loss_pct} % perdido` : "no se encontró"}</dd></div>
          </dl>
          {r.times.length > 0 && <Bars times={r.times} />}
          {r.router && r.avg != null && r.router.avg != null && r.avg > 80 && r.router.avg < 10 && (
            <p className="muted">Tu router responde rápido y Internet lento: el cuello de botella está fuera de tu red local (proveedor o servidor lejano).</p>
          )}
        </div>
      )}
    </section>
  );
}
