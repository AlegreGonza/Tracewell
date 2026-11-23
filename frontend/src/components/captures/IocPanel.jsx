import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";

// Lista de indicadores de compromiso
export default function IocPanel({ refreshKey, onChange, onError }) {
  const [status, setStatus] = useState(null);
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .iocs(ctl.signal)
      .then(setStatus)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [onError, refreshKey]);

  async function run(action) {
    setBusy(true);
    try {
      setStatus(await action());
      onChange?.();
    } catch (e) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  }

  function load(e) {
    e.preventDefault();
    if (path.trim()) run(() => api.loadIocs(path.trim()));
  }

  const loaded = status?.loaded === true;
  return (
    <section className="card" aria-labelledby="ioc-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="ioc-title">Indicadores (IOC)</h2>
          <HelpTip topic="ioc" />
        </div>
        <span className="muted" role="status">
          {loaded
            ? `${status.source}: ${status.ips} IP · ${status.networks} redes · ${status.domains} dominios · ${status.sessions} sesiones coinciden`
            : "Sin lista cargada"}
        </span>
      </div>
      <form className="ioc-form" onSubmit={load}>
        <label className="sr-only" htmlFor="ioc-path">Ruta del archivo de indicadores</label>
        <input
          id="ioc-path"
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="Ruta de un archivo: texto (un indicador por línea), CSV con columna value o STIX 2.1 (.json)"
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
        />
        <button type="submit" disabled={busy || !path.trim()}>Cargar lista</button>
        {loaded && (
          <button type="button" className="link" disabled={busy} onClick={() => run(api.clearIocs)}>
            Quitar
          </button>
        )}
      </form>
    </section>
  );
}
