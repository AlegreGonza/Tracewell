import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import { useAction } from "../../controllers/useAction.js";

const MARK = { true: "✔", false: "✘", null: "–" };
const LABEL = { true: "bien", false: "falla", null: "omitido" };

// «¿Hay Internet?»: revisa capa por capa y dice dónde se corta
export default function InternetCheckView() {
  const check = useAction((s) => api.supportInternet(s));
  const r = check.result;

  return (
    <section className="card" aria-labelledby="inet-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="inet-title">¿Hay Internet?</h2>
          <HelpTip topic="soporte_internet" />
        </div>
      </div>
      <div className="pad">
        <button type="button" onClick={() => check.run()} disabled={check.loading}>
          {check.loading ? "Comprobando…" : "Comprobar ahora"}
        </button>
        <p className="muted">Abre una conexión corta a 1.1.1.1 y 8.8.8.8 y le pide a tu DNS la dirección de unos sitios conocidos. No cambia nada.</p>
        {check.error && <p className="banner banner-error" role="alert">{check.error}</p>}
      </div>
      {r && (
        <div className="pad">
          <div className={`verdict ${r.ok ? "verdict-ok" : "verdict-bad"}`} role="status">
            <strong>{r.summary}</strong>
            {r.advice && <p>{r.advice}</p>}
            {r.command && (
              <p>
                Si querés, podés ejecutarlo vos: <code>{r.command}</code> <span className="muted">(Tracewell no lo ejecuta)</span>
              </p>
            )}
          </div>
          <ol className="steps-list">
            {r.steps.map((s) => (
              <li key={s.code} className={`step step-${String(s.ok)}`}>
                <span className="step-mark" aria-label={LABEL[String(s.ok)]}>{MARK[String(s.ok)]}</span>
                <div>
                  <strong>{s.title}</strong>
                  <div className="muted">{s.detail}</div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}
