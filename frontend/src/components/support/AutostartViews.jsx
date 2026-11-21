import { useMemo, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import { HINT_LABEL } from "./hints.js";
import RefreshButton from "./RefreshButton.jsx";
import { useLoad } from "../../controllers/useLoad.js";

const Hints = ({ hints }) =>
  hints.map((h) => (
    <div key={h.code} className="note-chip risky" title={h.text}>{HINT_LABEL[h.code] ?? h.code}</div>
  ));

// «Servicios»: programas que el sistema arranca solo y corren sin ventana. Solo lectura.
export function ServicesView({ active }) {
  const [query, setQuery] = useState("");
  const [onlyRunning, setOnlyRunning] = useState(true);
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.systemServices(s), { active });

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.items ?? []).filter(
      (r) =>
        (!onlyRunning || r.status === "running") &&
        (!q || [r.name, r.display, r.path, r.user].some((v) => v && String(v).toLowerCase().includes(q))),
    );
  }, [data, query, onlyRunning]);

  return (
    <section className="card" aria-labelledby="services-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="services-title">Servicios</h2>
          <HelpTip topic="sistema_servicios" />
        </div>
        <span className="muted">{data?.supported ? `${data.total} servicios` : ""}</span>
      </div>
      <div className="filters">
        <label>
          Buscar
          <input type="search" placeholder="nombre, ruta o cuenta" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <label className="inline">
          <input type="checkbox" checked={onlyRunning} onChange={(e) => setOnlyRunning(e.target.checked)} /> Solo los que están en marcha
        </label>
        <RefreshButton onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {data && !data.supported && <p className="banner banner-info" role="note">{data.reason}</p>}
      {!data && !error && <p className="muted pad skeleton">Leyendo los servicios…</p>}
      {data?.supported && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Servicio</th>
                <th scope="col">Estado</th>
                <th scope="col">Arranque</th>
                <th scope="col">Cuenta</th>
                <th scope="col">Programa</th>
                <th scope="col">Pistas</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name}>
                  <td title={r.name}>{r.display ?? r.name}</td>
                  <td>{r.status}</td>
                  <td>{r.start ?? <span className="muted">—</span>}</td>
                  <td className="mono">{r.user ?? <span className="muted">—</span>}</td>
                  <td className="mono break">{r.path ?? <span className="muted">—</span>}</td>
                  <td><Hints hints={r.hints} /></td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={6} className="muted">Nada para mostrar.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// «Programas de inicio»: lo que se ejecuta al arrancar la sesión. Solo lectura.
export function StartupView({ active }) {
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.systemStartup(s), { active });

  return (
    <section className="card" aria-labelledby="startup-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="startup-title">Programas de inicio</h2>
          <HelpTip topic="sistema_inicio" />
        </div>
        <RefreshButton link onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {data && !data.supported && <p className="banner banner-info" role="note">{data.reason}</p>}
      {!data && !error && <p className="muted pad skeleton">Leyendo el inicio…</p>}
      {data?.supported && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Nombre</th>
                <th scope="col">Dónde está anotado</th>
                <th scope="col">Se ejecuta</th>
                <th scope="col">Pistas</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((r, i) => (
                <tr key={`${r.where}-${r.name}-${i}`}>
                  <td>{r.name}</td>
                  <td>{r.where}</td>
                  <td className="mono break">{r.command}</td>
                  <td><Hints hints={r.hints} /></td>
                </tr>
              ))}
              {data.items.length === 0 && <tr><td colSpan={4} className="muted">No hay programas de inicio registrados.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
