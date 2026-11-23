import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";

const EMPTY = {
  name: "", severity: "medium", description: "", protocol: "any", src_ip: "", dst_ip: "",
  port: "0", min_events: "20", window_seconds: "60",
};
const SEVERITIES = [["low", "Baja"], ["medium", "Media"], ["high", "Alta"], ["critical", "Crítica"]];
const PROTOCOLS = [["any", "Cualquiera"], ["tcp", "TCP"], ["udp", "UDP"]];
const DEBOUNCE_MS = 300;

// Convierte lo escrito en el formulario al cuerpo de la API; null si un número todavía no es válido.
export function toBody(form) {
  const port = Number(form.port), minEvents = Number(form.min_events), window = Number(form.window_seconds);
  if (![port, minEvents, window].every(Number.isFinite) || form.port === "" || form.min_events === "" || form.window_seconds === "") return null;
  return { ...form, port, min_events: minEvents, window_seconds: window };
}

// «Reglas»: arma una alerta nueva (filtros + umbral), muestra el YAML en vivo y cuántas sesiones y alertas daría
// con la captura abierta ANTES de guardarla. Guardar crea un archivo nuevo en rules/; nunca toca las reglas existentes.
// Todo lo que viene del servidor o de la captura se muestra como texto (React lo escapa).
export default function RulesPanel({ onError, refreshKey }) {
  const [form, setForm] = useState(EMPTY);
  const [rules, setRules] = useState(null);
  const [example, setExample] = useState(null);
  const [preview, setPreview] = useState(null);
  const [problem, setProblem] = useState(null);
  const [saved, setSaved] = useState(null);
  const [saving, setSaving] = useState(false);

  const loadRules = useCallback(() => {
    return api.rules().then((r) => {
      setRules(r.items);
      setExample(r.example);
    }).catch((e) => onError(e.message));
  }, [onError]);

  useEffect(() => { loadRules(); }, [loadRules]);

  // Vista previa en vivo: espera a que termines de escribir y consulta al servidor (sin guardar nada).
  useEffect(() => {
    const body = toBody(form);
    if (!form.name.trim() || body === null) {
      setPreview(null);
      setProblem(form.name.trim() ? "Completá los números (puerto, eventos y ventana)." : null);
      return undefined;
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => {
      api
        .previewRule(body, ctl.signal)
        .then((r) => { setPreview(r); setProblem(null); })
        .catch((e) => {
          if (e.name === "AbortError") return;
          setPreview(null);
          setProblem(e.message);
        });
    }, DEBOUNCE_MS);
    return () => { clearTimeout(timer); ctl.abort(); };
  }, [form, refreshKey]);

  const set = (key) => (e) => { setSaved(null); setForm((f) => ({ ...f, [key]: e.target.value })); };

  function loadExample() {
    if (!example) return;
    setSaved(null);
    setForm({ ...EMPTY, ...Object.fromEntries(Object.entries(example).map(([k, v]) => [k, String(v)])) });
  }

  async function save(e) {
    e.preventDefault();
    const body = toBody(form);
    if (body === null) return;
    setSaving(true);
    try {
      setSaved(await api.saveRule(body));
      await loadRules();
    } catch (err) {
      setProblem(err.message);
    } finally {
      setSaving(false);
    }
  }

  const matches = preview?.matches;
  const custom = (rules ?? []).filter((r) => r.custom);
  return (
    <section className="card rules-panel" aria-labelledby="rules-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="rules-title">Crear una alerta nueva</h2>
          <HelpTip topic="rules" />
        </div>
        <button type="button" onClick={loadExample} disabled={!example}>Cargar un ejemplo</button>
      </div>
      <p className="muted">
        Elegí qué tráfico mirar y cuántas veces tiene que repetirse en un rato para que salte la alerta. Se guarda como un archivo
        nuevo en <code>rules/</code>; las reglas que ya existen no se tocan. La regla nueva vale desde la próxima captura que abras.
      </p>

      <div className="rules-grid">
        <form className="rules-form" onSubmit={save} aria-label="Datos de la regla">
          <label>Nombre
            <input value={form.name} onChange={set("name")} maxLength={80} placeholder="Ej.: Muchas conexiones al SSH" />
          </label>
          <label>Severidad
            <select value={form.severity} onChange={set("severity")}>
              {SEVERITIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <label className="wide">Descripción
            <textarea value={form.description} onChange={set("description")} rows={2} maxLength={500} placeholder="Qué significa que salte esta alerta" />
          </label>
          <fieldset className="wide">
            <legend>Qué tráfico mirar (todo es opcional)</legend>
            <label>Protocolo
              <select value={form.protocol} onChange={set("protocol")}>
                {PROTOCOLS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </label>
            <label>IP o red de origen
              <input value={form.src_ip} onChange={set("src_ip")} placeholder="Ej.: 192.168.1.0/24" inputMode="text" />
            </label>
            <label>IP o red de destino
              <input value={form.dst_ip} onChange={set("dst_ip")} placeholder="Ej.: 10.0.0.5" inputMode="text" />
            </label>
            <label>Puerto de destino (0 = cualquiera)
              <input type="number" min="0" max="65535" value={form.port} onChange={set("port")} />
            </label>
          </fieldset>
          <fieldset className="wide">
            <legend>Umbral</legend>
            <label>Cantidad de eventos
              <input type="number" min="2" value={form.min_events} onChange={set("min_events")} />
            </label>
            <label>En una ventana de (segundos)
              <input type="number" min="0.001" step="any" value={form.window_seconds} onChange={set("window_seconds")} />
            </label>
          </fieldset>
          <div className="wide rules-actions">
            <button type="submit" className="button-primary" disabled={saving || !form.name.trim() || toBody(form) === null || Boolean(problem)}>
              {saving ? "Guardando…" : "Guardar regla"}
            </button>
          </div>
        </form>

        <div className="rules-side">
          {problem && <p role="alert" className="banner banner-warn">{problem}</p>}
          {saved && (
            <p role="status" className="banner banner-info">
              Regla guardada en <code>rules/{saved.file}</code>. Se aplicará a la próxima captura que abras.
            </p>
          )}
          <h3>Vista previa con la captura abierta</h3>
          {preview === null ? (
            <p className="muted">Completá el nombre para ver la vista previa.</p>
          ) : matches ? (
            <div role="status" className="rules-preview">
              <p><strong>{matches.alerts.toLocaleString("es-AR")}</strong> alerta(s) y <strong>{matches.sessions.toLocaleString("es-AR")}</strong> sesión(es) coincidirían con esta captura. Todavía no se guardó nada.</p>
              {matches.sample.length > 0 && (
                <ul>
                  {matches.sample.map((a, i) => (
                    <li key={i} className="mono">{a.src_ip} → {a.dst_ip}: {a.evidence.events} eventos en {a.evidence.window_seconds} s</li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <p className="muted" role="status">Abrí una captura para ver cuántas sesiones y alertas daría. El YAML igual se muestra abajo.</p>
          )}
          {preview?.exists && <p className="banner banner-warn" role="note">Ya existe una regla con ese id: cambiá el nombre para poder guardarla.</p>}
          <h3>YAML resultante</h3>
          <pre className="rules-yaml" aria-label="YAML de la regla">{preview?.yaml ?? "# Completá el nombre para generar el YAML."}</pre>
        </div>
      </div>

      {custom.length > 0 && (
        <div className="rules-custom">
          <h3>Reglas creadas acá</h3>
          <ul>{custom.map((r) => <li key={r.id}><span className="mono">{r.id}</span> · {r.name}</li>)}</ul>
        </div>
      )}
    </section>
  );
}
