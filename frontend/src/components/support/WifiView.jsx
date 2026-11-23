import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import RefreshButton from "./RefreshButton.jsx";
import { Meter } from "./SystemOverview.jsx";
import { useAction } from "../../controllers/useAction.js";
import { useLoad } from "../../controllers/useLoad.js";

const when = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("es-AR");
};

// «Wi-Fi»: señal, canal y velocidad de la conexión actual, más el historial de conexiones
export default function WifiView({ active }) {
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.supportWifi(s), { every: 5000, active });
  const history = useAction((s) => api.supportWifiHistory(s));
  const h = history.result;

  return (
    <section className="card" aria-labelledby="wifi-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="wifi-title">Wi-Fi</h2>
          <HelpTip topic="soporte_wifi" />
        </div>
        <RefreshButton link onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {!data && !error && <p className="muted pad skeleton">Leyendo el Wi-Fi…</p>}
      {data && !data.available && <p className="banner banner-info" role="note">{data.reason}</p>}
      {data?.available && !data.connected && <p className="banner banner-info" role="note">{data.reason ?? "El Wi-Fi no está conectado a ninguna red."}</p>}
      {data?.available && data.connected && (
        <div className="pad">
          <Meter goodHigh label={`Señal${data.quality ? ` (${data.quality})` : ""}`} percent={data.signal} detail={data.quality === "débil" ? "La señal es débil: acercate al router o probá la banda de 2,4 GHz, que llega más lejos." : null} />
          <dl className="facts">
            <div><dt>Red (SSID)</dt><dd className="mono">{data.ssid}</dd></div>
            <div><dt>Canal / banda</dt><dd>{data.channel ?? "—"} / {data.band ?? "—"}</dd></div>
            <div><dt>Tipo de Wi-Fi</dt><dd>{data.radio ?? "—"}</dd></div>
            <div><dt>Seguridad</dt><dd>{data.auth ?? "—"}</dd></div>
            <div><dt>Velocidad (recibe / envía)</dt><dd>{data.rx != null ? `${data.rx} Mbps` : "—"} / {data.tx != null ? `${data.tx} Mbps` : "—"}</dd></div>
            <div><dt>Punto de acceso (BSSID)</dt><dd className="mono">{data.bssid ?? "—"}</dd></div>
          </dl>
        </div>
      )}

      <div className="card-head">
        <h3>Historial de conexiones y desconexiones</h3>
      </div>
      <div className="pad">
        <button type="button" onClick={() => history.run()} disabled={history.loading}>
          {history.loading ? "Leyendo…" : h ? "Volver a leer" : "Ver el historial"}
        </button>
        {history.error && <p className="banner banner-error" role="alert">{history.error}</p>}
        {h && !h.available && <p className="banner banner-info" role="note">{h.reason}</p>}
        {h?.available && (
          <>
            <p className="muted">{h.events.length} eventos recientes · {h.disconnections} desconexiones</p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th scope="col">Cuándo</th><th scope="col">Qué pasó</th><th scope="col">Detalle del sistema</th></tr>
                </thead>
                <tbody>
                  {h.events.map((e, i) => (
                    <tr key={`${e.time}-${i}`}>
                      <td className="mono">{when(e.time)}</td>
                      <td><span className={`pill ${e.kind === "conectado" ? "pill-ok" : "pill-off"}`}>{e.kind}</span></td>
                      <td className="muted">{e.message}</td>
                    </tr>
                  ))}
                  {h.events.length === 0 && <tr><td colSpan={3} className="muted">Windows no registró eventos de Wi-Fi.</td></tr>}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
