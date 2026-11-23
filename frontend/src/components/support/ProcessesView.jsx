import { useMemo, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";
import { HINT_LABEL } from "./hints.js";
import ProcessDetail from "./ProcessDetail.jsx";
import RefreshButton from "./RefreshButton.jsx";
import { useLoad } from "../../controllers/useLoad.js";

const SORTS = [
  ["ram", "Memoria (RAM)"],
  ["cpu", "Procesador"],
  ["name", "Nombre"],
  ["pid", "PID"],
];

// «Procesos»: lo que corre en este equipo, ordenable por RAM o procesador
export default function ProcessesView({ active }) {
  const [sort, setSort] = useState("ram");
  const [query, setQuery] = useState("");
  const [onlyHints, setOnlyHints] = useState(false);
  const [auto, setAuto] = useState(false);
  const [selected, setSelected] = useState(null);
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.systemProcesses({ sort, limit: 600 }, s), {
    every: auto ? 5000 : 0,
    active,
    deps: [sort], // el orden lo hace el servidor: al cambiarlo se vuelve a pedir
  });

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.items ?? []).filter(
      (r) =>
        (!onlyHints || r.hints.length > 0) &&
        (!q || [r.name, r.exe, r.user, String(r.pid)].some((v) => v && String(v).toLowerCase().includes(q))),
    );
  }, [data, query, onlyHints]);

  const withHints = (data?.items ?? []).filter((r) => r.hints.length > 0).length;

  return (
    <div className={selected ? "layout with-detail" : "layout"}>
      <section className="card col" aria-labelledby="procs-title">
        <div className="card-head">
          <div className="head-title">
            <h2 id="procs-title">Procesos</h2>
            <HelpTip topic="sistema_procesos" />
          </div>
          <span className="muted">{data ? `${data.total} en marcha · ${withHints} con pistas` : ""}</span>
        </div>
        <div className="filters">
          <label>
            Buscar
            <input type="search" placeholder="nombre, ruta, usuario o PID" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <label>
            Ordenar por
            <select value={sort} onChange={(e) => setSort(e.target.value)}>
              {SORTS.map(([v, t]) => (
                <option key={v} value={v}>{t}</option>
              ))}
            </select>
          </label>
          <label className="inline">
            <input type="checkbox" checked={onlyHints} onChange={(e) => setOnlyHints(e.target.checked)} /> Solo con pistas
          </label>
          <label className="inline">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Actualizar cada 5 s
          </label>
          <RefreshButton onClick={reload} loading={loading} updatedAt={updatedAt} />
        </div>
        {error && <p className="banner banner-error" role="alert">{error}</p>}
        {!data && !error && <p className="muted pad skeleton">Leyendo los procesos…</p>}
        {data && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Nombre</th>
                  <th scope="col" className="num">PID</th>
                  <th scope="col">Usuario</th>
                  <th scope="col" className="num">RAM</th>
                  <th scope="col" className="num">Procesador</th>
                  <th scope="col" className="num">Conexiones</th>
                  <th scope="col">Pistas</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.pid} className={selected === r.pid ? "selected" : ""}>
                    <td className="mono">
                      <button type="button" className="link" onClick={() => setSelected(r.pid)} title={r.exe ?? "Ruta no disponible"}>
                        {r.name ?? `PID ${r.pid}`}
                      </button>
                    </td>
                    <td className="num mono">{r.pid}</td>
                    <td className="mono">{r.user ?? <span className="muted">—</span>}</td>
                    <td className="num">{r.rss != null ? formatBytes(r.rss) : "—"}</td>
                    <td className="num">{r.cpu != null ? `${r.cpu.toFixed(1)} %` : "—"}</td>
                    <td className="num">{r.connections || <span className="muted">0</span>}</td>
                    <td>
                      {r.hints.map((h) => (
                        <div key={h.code} className="note-chip risky" title={h.text}>{HINT_LABEL[h.code] ?? h.code}</div>
                      ))}
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr><td colSpan={7} className="muted">Ningún proceso coincide con la búsqueda.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {selected && <ProcessDetail pid={selected} onClose={() => setSelected(null)} onSelect={setSelected} />}
    </div>
  );
}
