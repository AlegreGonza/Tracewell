import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

// "Seguir la conversación": lo que se dijo en una sesión TCP, por turnos (como Follow TCP Stream de Wireshark).
// Los datos vienen del tráfico y pueden ser hostiles: se muestran SIEMPRE como texto, nunca como HTML.
// Ojo: con protocolos en claro (FTP, HTTP, Telnet) esto muestra el contenido tal cual, contraseñas incluidas.
export default function StreamView({ session, onError }) {
  const [state, setState] = useState({ status: "idle", data: null });

  useEffect(() => {
    setState({ status: "idle", data: null });
  }, [session.id]);

  if (session.protocol !== "TCP") return null;

  async function load() {
    setState({ status: "loading", data: null });
    try {
      setState({ status: "ready", data: await api.stream(session.id) });
    } catch (e) {
      onError(e.message);
      setState({ status: "idle", data: null });
    }
  }

  const { status, data } = state;
  return (
    <section className="stream" aria-labelledby="stream-title">
      <h3 id="stream-title">
        Conversación <HelpTip topic="conversacion" />
      </h3>
      {status === "idle" && (
        <div className="stream-actions">
          <button type="button" onClick={load}>Ver la conversación</button>
          <span className="muted">Reconstruye lo que se dijo en esta sesión TCP.</span>
        </div>
      )}
      {status === "loading" && <p className="empty">Reconstruyendo…</p>}
      {status === "ready" && <StreamBody data={data} />}
    </section>
  );
}

function StreamBody({ data }) {
  if (data.encrypted) {
    return (
      <p className="banner banner-warn" role="note">
        Sesión cifrada (TLS): el contenido no se puede leer, solo sus metadatos ({formatBytes(data.origin_bytes)} del
        origen y {formatBytes(data.destination_bytes)} del destino).
      </p>
    );
  }
  if (data.chunks.length === 0) {
    return <p className="empty">Esta sesión no tiene datos (solo conexión, confirmaciones o cierre).</p>;
  }
  return (
    <div className="stream-body">
      {data.truncated && (
        <p className="banner banner-warn" role="note">
          Conversación recortada: se muestran solo los primeros datos de la sesión.
        </p>
      )}
      <p className="muted">
        Origen (quien inició): {formatBytes(data.origin_bytes)} · Destino: {formatBytes(data.destination_bytes)}
      </p>
      {data.chunks.map((c, i) =>
        c.gap !== undefined ? (
          <p key={i} className="chunk-gap muted mono">
            [faltan {c.gap.toLocaleString("es-AR")} bytes: no están en la captura]
          </p>
        ) : (
          <div key={i} className={`chunk chunk-${c.from}`}>
            <span className="chunk-who">
              {c.from === "origen" ? "→ Origen" : "← Destino"} · {formatBytes(c.bytes)}
            </span>
            <pre className="mono">{c.text}</pre>
          </div>
        ),
      )}
    </div>
  );
}
