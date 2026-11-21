import { useMemo, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import RefreshButton from "./RefreshButton.jsx";
import { useLoad } from "../../controllers/useLoad.js";

const EXPOSURE_CLASS = { local: "expo-local", todas: "expo-all", especifica: "expo-some" };

// «Puertos abiertos»: lo que escucha en este equipo, con su programa y quién puede llamarlo.
export function PortsView({ active }) {
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [query, setQuery] = useState("");
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.systemPorts(s), { every: 0, active });

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.items ?? []).filter(
      (r) =>
        (!onlyOpen || r.exposure === "todas") &&
        (!q || [r.process, r.service, String(r.port), r.ip].some((v) => v && String(v).toLowerCase().includes(q))),
    );
  }, [data, onlyOpen, query]);
  const open = (data?.items ?? []).filter((r) => r.exposure === "todas").length;

  return (
    <section className="card" aria-labelledby="ports-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="ports-title">Puertos abiertos</h2>
          <HelpTip topic="sistema_puertos" />
        </div>
        <span className="muted">{data ? `${data.total} en escucha · ${open} abiertos a toda la red` : ""}</span>
      </div>
      <div className="filters">
        <label>
          Buscar
          <input type="search" placeholder="programa, servicio o puerto" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <label className="inline">
          <input type="checkbox" checked={onlyOpen} onChange={(e) => setOnlyOpen(e.target.checked)} /> Solo abiertos a toda la red
        </label>
        <RefreshButton onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {data?.limited && (
        <p className="banner banner-warn" role="note">Sin permisos de administrador no se ve qué programa tiene cada puerto. Abrí Tracewell como administrador para verlo.</p>
      )}
      {!data && !error && <p className="muted pad skeleton">Leyendo los puertos…</p>}
      {data && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col" className="num">Puerto</th>
                <th scope="col">Protocolo</th>
                <th scope="col">Servicio</th>
                <th scope="col">Quién puede llamar</th>
                <th scope="col">Dirección</th>
                <th scope="col">Programa</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.proto}-${r.ip}-${r.port}-${r.pid}`}>
                  <td className="num mono">{r.port}</td>
                  <td>{r.proto}</td>
                  <td>{r.service ?? <span className="muted">—</span>}</td>
                  <td><span className={`expo ${EXPOSURE_CLASS[r.exposure] ?? ""}`}>{r.exposure_text}</span></td>
                  <td className="mono">{r.ip}</td>
                  <td className="mono">{r.process ? `${r.process} (${r.pid})` : <span className="muted">—</span>}</td>
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

// «Conexiones activas»: con quién habla este equipo ahora y qué programa lo hace.
export function ConnectionsView({ active }) {
  const [query, setQuery] = useState("");
  const [onlyPublic, setOnlyPublic] = useState(false);
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.systemConnections(s), { every: 5000, active });

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.items ?? []).filter(
      (r) =>
        (!onlyPublic || r.scope === "publica") &&
        (!q || [r.process, r.remote, r.owner, r.service].some((v) => v && String(v).toLowerCase().includes(q))),
    );
  }, [data, query, onlyPublic]);

  return (
    <section className="card" aria-labelledby="conns-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="conns-title">Conexiones activas</h2>
          <HelpTip topic="sistema_conexiones" />
        </div>
        <span className="muted">{data ? `${data.total} conexiones (se actualiza cada 5 s)` : ""}</span>
      </div>
      <div className="filters">
        <label>
          Buscar
          <input type="search" placeholder="programa, IP o dueño" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <label className="inline">
          <input type="checkbox" checked={onlyPublic} onChange={(e) => setOnlyPublic(e.target.checked)} /> Solo hacia internet
        </label>
        <RefreshButton onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {data?.limited && data.total === 0 && (
        <p className="banner banner-warn" role="note">El sistema no deja listar las conexiones sin permisos de administrador. Abrí Tracewell como administrador para verlas.</p>
      )}
      {!data && !error && <p className="muted pad skeleton">Leyendo las conexiones…</p>}
      {data && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Programa</th>
                <th scope="col">Desde</th>
                <th scope="col">Hacia</th>
                <th scope="col">Servicio</th>
                <th scope="col">Dueño del rango</th>
                <th scope="col">Estado</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={`${r.local}-${r.remote}-${i}`}>
                  <td className="mono">{r.process ? `${r.process} (${r.pid})` : <span className="muted">—</span>}</td>
                  <td className="mono">{r.local ?? "—"}</td>
                  <td className="mono">{r.remote ?? "—"}</td>
                  <td>{r.service ?? <span className="muted">—</span>}</td>
                  <td>{r.owner ?? <span className="muted">{r.scope === "publica" ? "desconocido" : "red local"}</span>}</td>
                  <td>{r.status}</td>
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
