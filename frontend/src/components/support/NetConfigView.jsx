import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import RefreshButton from "./RefreshButton.jsx";
import { useAction } from "../../controllers/useAction.js";
import { useLoad } from "../../controllers/useLoad.js";

const dash = (v) => (v == null || v === "" ? "—" : v);
const list = (a) => (a && a.length > 0 ? a.join(", ") : "—");

// «Configuración de red»: cada adaptador con su IP, puerta de enlace y DNS. Solo lectura.
export default function NetConfigView({ active }) {
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.supportConfig(s), { active });
  const raw = useAction((s) => api.supportConfigRaw(s));

  return (
    <section className="card" aria-labelledby="netcfg-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="netcfg-title">Configuración de red</h2>
          <HelpTip topic="soporte_config" />
        </div>
        <RefreshButton link onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {!data && !error && <p className="muted pad skeleton">Leyendo la configuración (puede tardar unos segundos)…</p>}
      {data && (
        <>
          <p className="muted pad-s">Equipo: <span className="mono">{data.hostname}</span></p>
          <div className="adapter-grid">
            {data.adapters.map((a) => (
              <article key={a.name} className={`adapter${a.up ? "" : " down"}`}>
                <h3>
                  {a.name} <span className={`pill ${a.up ? "pill-ok" : "pill-off"}`}>{a.up ? "conectado" : "desconectado"}</span>
                </h3>
                {a.apipa && (
                  <p className="banner banner-warn" role="note">
                    Tiene una IP 169.254.x.x: la PC no consiguió una IP del router (DHCP), así que no tiene Internet. Revisá el cable o el Wi-Fi y que el router reparta IPs.
                  </p>
                )}
                <dl className="facts">
                  <div><dt>Descripción</dt><dd>{dash(a.description)}</dd></div>
                  <div><dt>IP (IPv4)</dt><dd className="mono">{a.ipv4.length ? a.ipv4.map((v) => `${v.ip} / ${v.mask}`).join(", ") : "—"}</dd></div>
                  <div><dt>IP automática (DHCP)</dt><dd>{a.dhcp == null ? "—" : a.dhcp ? "Sí" : "No: IP fija"}</dd></div>
                  <div><dt>Puerta de enlace</dt><dd className="mono">{list(a.gateway)}</dd></div>
                  <div><dt>Servidores DNS</dt><dd className="mono break">{list(a.dns)}</dd></div>
                  <div><dt>IPv6</dt><dd className="mono break">{list(a.ipv6)}</dd></div>
                  <div><dt>Dirección física (MAC)</dt><dd className="mono">{dash(a.mac)}</dd></div>
                  <div><dt>Velocidad / MTU</dt><dd>{a.speed_mbps ? `${a.speed_mbps} Mbps` : "—"} / {dash(a.mtu)}</dd></div>
                </dl>
              </article>
            ))}
          </div>
          <details className="pad" onToggle={(e) => e.currentTarget.open && !raw.result && !raw.loading && raw.run()}>
            <summary>Ver la salida completa del sistema</summary>
            {raw.loading && <p className="muted">Leyendo…</p>}
            {raw.error && <p className="banner banner-error" role="alert">{raw.error}</p>}
            {raw.result && (raw.result.available ? (
              <>
                <p className="muted">Comando: <code>{raw.result.command}</code></p>
                <pre className="rawout">{raw.result.text}</pre>
              </>
            ) : (
              <p className="muted">{raw.result.reason}</p>
            ))}
          </details>
        </>
      )}
    </section>
  );
}
