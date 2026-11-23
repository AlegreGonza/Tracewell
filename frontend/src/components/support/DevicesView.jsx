import { useEffect } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import { useAction } from "../../controllers/useAction.js";

// «Dispositivos de la red»: quién está en tu red local
export default function DevicesView() {
  const list = useAction((scan, s) => api.supportDevices(scan, s));
  const { run } = list;
  useEffect(() => {
    run(false);
  }, [run]);
  const r = list.result;

  return (
    <section className="card" aria-labelledby="dev-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="dev-title">Dispositivos de la red</h2>
          <HelpTip topic="soporte_dispositivos" />
        </div>
        <span className="muted">{r ? `${r.devices.length} dispositivos · red ${r.subnets.join(", ") || "—"}` : ""}</span>
      </div>
      <div className="filters">
        <button type="button" onClick={() => run(true)} disabled={list.loading}>
          {list.loading ? "Buscando…" : "Buscar en la red"}
        </button>
        <button type="button" onClick={() => run(false)} disabled={list.loading}>Ver lo que ya conoce mi PC</button>
        <span className="muted">«Buscar» manda un ping a cada dirección de tu red (puede tardar 10–20 segundos). No cambia nada.</span>
      </div>
      {list.error && <p className="banner banner-error" role="alert">{list.error}</p>}
      {r && !r.vendor_db && (
        <p className="banner banner-info" role="note">
          No hay base de fabricantes, así que no se muestra la marca de cada dispositivo. Para activarla, colocá la lista oficial de la IEEE (oui.csv) en la carpeta <code>data</code> de Tracewell.
        </p>
      )}
      {!r && !list.error && <p className="muted pad skeleton">Leyendo la tabla de tu PC…</p>}
      {r && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">IP</th>
                <th scope="col">Nombre</th>
                <th scope="col">Dirección física (MAC)</th>
                <th scope="col">Marca</th>
                <th scope="col">Notas</th>
              </tr>
            </thead>
            <tbody>
              {r.devices.map((d) => (
                <tr key={`${d.ip}-${d.mac}`}>
                  <td className="mono">{d.ip}</td>
                  <td className="mono">{d.hostname ?? <span className="muted">—</span>}</td>
                  <td className="mono">{d.mac}</td>
                  <td>
                    {d.vendor ?? <span className="muted">{d.random_mac ? "MAC privada (aleatoria)" : "desconocida"}</span>}
                  </td>
                  <td>
                    {d.is_gateway && <span className="pill pill-ok">router</span>}
                    {d.is_self && <span className="pill pill-off">esta PC</span>}
                  </td>
                </tr>
              ))}
              {r.devices.length === 0 && <tr><td colSpan={5} className="muted">Todavía no hay vecinos conocidos: probá «Buscar en la red».</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
