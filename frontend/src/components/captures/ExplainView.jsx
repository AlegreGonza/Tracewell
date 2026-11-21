import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatTime } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

// Diagrama de la conexión paso a paso (como el «Flow Graph» de Wireshark): cada fila es un paquete importante y su flecha
// muestra quién se lo manda a quién. Todo es texto que viene del análisis: nunca se interpreta como HTML.
export function Ladder({ steps, origin, destination }) {
  return (
    <div className="ladder">
      <div className="ladder-head mono">
        <span>Origen · {origin}</span>
        <span>Destino · {destination}</span>
      </div>
      <ol>
        {steps.map((s, i) => {
          const dir = s.who === "origen" ? "origen" : s.who === "destino" ? "destino" : "ambos";
          const spoken = dir === "origen" ? "Origen → Destino" : dir === "destino" ? "Destino → Origen" : "";
          return (
            <li key={i} className={`step step-${dir}`} aria-label={`${spoken ? spoken + ": " : ""}${s.label}. ${s.detail}`}>
              <span className="step-label mono">{s.label}</span>
              <span className="step-arrow" aria-hidden="true">{dir === "origen" ? "───▶" : dir === "destino" ? "◀───" : "· · ·"}</span>
              <span className="step-detail muted">
                {s.detail}
                {s.ts != null && <span className="mono"> · {formatTime(s.ts)}</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

// «En palabras simples»: la sesión contada como frases, más el diagrama de la conexión.
export default function ExplainView({ session, onError }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    setData(null);
    const ctl = new AbortController();
    api
      .explain(session.id, ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [session.id, onError]);

  return (
    <section className="explain" aria-labelledby="explain-title">
      <h3 id="explain-title">
        En palabras simples <HelpTip topic="explicacion" />
      </h3>
      {data === null ? (
        <p className="empty">Analizando la sesión…</p>
      ) : (
        <>
          <ul className="explain-list">
            {data.summary.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
          {data.steps.length > 0 && <Ladder steps={data.steps} origin={session.src_ip} destination={session.dst_ip} />}
        </>
      )}
    </section>
  );
}
