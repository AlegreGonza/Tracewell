import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";
import { useAction } from "../../controllers/useAction.js";

const PORT_STATE = { abierto: "abierto", cerrado: "cerrado", sin_respuesta: "sin respuesta (¿filtrado?)", error: "error" };

function Tool({ title, children }) {
  return (
    <article className="tool">
      <h3>{title}</h3>
      {children}
    </article>
  );
}

const Err = ({ msg }) => (msg ? <p className="banner banner-error" role="alert">{msg}</p> : null);

function PingTool() {
  const [host, setHost] = useState("");
  const [history, setHistory] = useState([]);
  const [continuous, setContinuous] = useState(false);
  const once = useAction((h, s) => api.supportPing(h, 4, s));

  // Ping continuo
  useEffect(() => {
    if (!continuous || !host.trim()) return undefined;
    let alive = true;
    async function tick() {
      try {
        const r = await api.supportPing(host, 1);
        if (alive) setHistory((h) => [{ t: Date.now(), ok: r.available && r.received > 0, ms: r.avg }, ...h].slice(0, 60));
      } catch {
        if (alive) setHistory((h) => [{ t: Date.now(), ok: false, ms: null }, ...h].slice(0, 60));
      }
    }
    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [continuous, host]);

  const r = once.result;
  const lost = history.filter((h) => !h.ok).length;
  return (
    <Tool title="Ping">
      <form className="filters" onSubmit={(e) => { e.preventDefault(); once.run(host); }}>
        <label>Equipo o IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.1 o www.google.com" /></label>
        <button type="submit" disabled={once.loading || !host.trim()}>{once.loading ? "Enviando…" : "Hacer ping (4)"}</button>
        <label className="inline"><input type="checkbox" checked={continuous} onChange={(e) => setContinuous(e.target.checked)} disabled={!host.trim()} /> Ping continuo</label>
      </form>
      <Err msg={once.error} />
      {r && !r.available && <p className="muted">{r.reason}</p>}
      {r?.available && (
        <p>
          {r.received} de {r.sent} respuestas ({r.loss_pct} % perdido) ·{" "}
          {r.avg != null ? `promedio ${r.avg} ms (mín ${r.min}, máx ${r.max})` : "sin respuesta"}
        </p>
      )}
      {history.length > 0 && (
        <>
          <p className="muted">{history.length} pings · {lost} sin respuesta</p>
          <ul className="plain-list mono small pinglog">
            {history.map((h) => (
              <li key={h.t} className={h.ok ? "" : "bad"}>{new Date(h.t).toLocaleTimeString("es-AR")} · {h.ok ? `${h.ms} ms` : "sin respuesta"}</li>
            ))}
          </ul>
        </>
      )}
    </Tool>
  );
}

function TraceTool() {
  const [host, setHost] = useState("");
  const trace = useAction((h, s) => api.supportTraceroute(h, s));
  const r = trace.result;
  return (
    <Tool title="Traza de ruta (tracert)">
      <form className="filters" onSubmit={(e) => { e.preventDefault(); trace.run(host); }}>
        <label>Destino<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="www.google.com" /></label>
        <button type="submit" disabled={trace.loading || !host.trim()}>{trace.loading ? "Trazando… (puede tardar 30 s)" : "Trazar"}</button>
      </form>
      <Err msg={trace.error} />
      {r && !r.available && <p className="muted">{r.reason}</p>}
      {r?.available && (
        <div className="table-wrap">
          <table>
            <thead><tr><th scope="col" className="num">Salto</th><th scope="col">Equipo</th><th scope="col">Tiempos</th></tr></thead>
            <tbody>
              {r.hops.map((h) => (
                <tr key={h.n}>
                  <td className="num">{h.n}</td>
                  <td className="mono">{h.ips.length ? h.ips.join(", ") : <span className="muted">sin respuesta</span>}</td>
                  <td className="mono">{h.times.length ? h.times.map((t) => `${t} ms`).join(" · ") : "—"}</td>
                </tr>
              ))}
              {r.hops.length === 0 && <tr><td colSpan={3} className="muted">No se obtuvieron saltos.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </Tool>
  );
}

function PortsTool() {
  const [host, setHost] = useState("");
  const [ports, setPorts] = useState("22,80,443,3389");
  const check = useAction((h, p, s) => api.supportPorts(h, p, s));
  const r = check.result;
  return (
    <Tool title="Puertos de un equipo">
      <form className="filters" onSubmit={(e) => { e.preventDefault(); check.run(host, ports); }}>
        <label>Equipo o IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.20" /></label>
        <label>Puertos (hasta 20)<input value={ports} onChange={(e) => setPorts(e.target.value)} /></label>
        <button type="submit" disabled={check.loading || !host.trim()}>{check.loading ? "Probando…" : "Probar"}</button>
      </form>
      <Err msg={check.error} />
      {r && (
        <ul className="plain-list mono">
          {r.results.map((p) => (
            <li key={p.port}>
              {p.port}{p.service ? ` (${p.service})` : ""}: <strong>{PORT_STATE[p.state] ?? p.state}</strong>{p.ms != null ? ` · ${p.ms} ms` : ""}
            </li>
          ))}
        </ul>
      )}
    </Tool>
  );
}

function RdpTool() {
  const [host, setHost] = useState("");
  const check = useAction((h, s) => api.supportRdp(h, 3389, s));
  const r = check.result;
  return (
    <Tool title="Acceso remoto (RDP)">
      <form className="filters" onSubmit={(e) => { e.preventDefault(); check.run(host); }}>
        <label>Equipo o IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.20" /></label>
        <button type="submit" disabled={check.loading || !host.trim()}>{check.loading ? "Probando…" : "Probar RDP"}</button>
      </form>
      <p className="muted">Manda una sola solicitud de conexión y se corta: no intenta iniciar sesión ni prueba contraseñas.</p>
      <Err msg={check.error} />
      {r && <p><strong>{r.summary}</strong></p>}
    </Tool>
  );
}

function TimeTool() {
  const [server, setServer] = useState("time.windows.com");
  const check = useAction((sv, s) => api.supportTime(sv, s));
  const r = check.result;
  return (
    <Tool title="Hora de la PC">
      <form className="filters" onSubmit={(e) => { e.preventDefault(); check.run(server); }}>
        <label>
          Comparar con
          <select value={server} onChange={(e) => setServer(e.target.value)}>
            {["time.windows.com", "pool.ntp.org", "time.cloudflare.com"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <button type="submit" disabled={check.loading}>{check.loading ? "Consultando…" : "Comprobar hora"}</button>
      </form>
      <p className="muted">Le pregunta la hora a ese servidor público. Solo compara: no cambia el reloj.</p>
      <Err msg={check.error} />
      {r && !r.available && <p className="muted">{r.reason}</p>}
      {r?.available && (
        <>
          <p><strong>{r.summary}</strong> Diferencia: {r.offset_seconds > 0 ? "+" : ""}{r.offset_seconds} s.</p>
          {r.command && <p>Si querés, podés ejecutarlo vos: <code>{r.command}</code> <span className="muted">(Tracewell no lo ejecuta)</span></p>}
        </>
      )}
    </Tool>
  );
}

function DuplicateIpTool() {
  const check = useAction((s) => api.supportDuplicateIp(s));
  const r = check.result;
  return (
    <Tool title="IP duplicada">
      <p className="muted">Pregunta por ARP quién tiene la IP de esta PC y revisa los avisos de conflicto que Windows ya anotó. La sonda necesita Npcap y abrir Tracewell como administrador.</p>
      <button type="button" onClick={() => check.run()} disabled={check.loading}>{check.loading ? "Revisando…" : "Revisar"}</button>
      <Err msg={check.error} />
      {r && (
        <>
          <p className={r.duplicate ? "verdict verdict-bad" : ""}><strong>{r.summary}</strong></p>
          {r.advice && <p>{r.advice}</p>}
          <ul className="plain-list small">
            {r.probes.map((p) => (
              <li key={`${p.adapter}-${p.ip}`} className="mono">
                {p.adapter} ({p.ip}): {p.probed ? (p.duplicate ? `¡contestó otra MAC! ${p.other_macs.join(", ")}` : "sin otros equipos con esa IP") : p.reason}
              </li>
            ))}
            {r.conflicts.map((c) => <li key={c.time} className="mono">Aviso de Windows ({c.time?.slice(0, 19).replace("T", " ")}): {c.message}</li>)}
          </ul>
        </>
      )}
    </Tool>
  );
}

// «Herramientas»: pruebas sueltas sobre un equipo que elijas. Ninguna cambia nada.
export default function ToolsView() {
  return (
    <section className="card" aria-labelledby="tools-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="tools-title">Herramientas</h2>
          <HelpTip topic="soporte_herramientas" />
        </div>
      </div>
      <div className="tools-grid">
        <PingTool />
        <TraceTool />
        <PortsTool />
        <RdpTool />
        <TimeTool />
        <DuplicateIpTool />
      </div>
    </section>
  );
}
