import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";

const REASON = {
  manual: "detenida manualmente",
  max_packets: "alcanzó el máximo de paquetes",
  max_seconds: "alcanzó el tiempo máximo",
  max_bytes: "alcanzó el tamaño máximo",
  error: "se detuvo por un error de escritura",
};

export default function LivePanel({ onAnalyzed, onError, disabled }) {
  const [open, setOpen] = useState(false);
  const [interfaces, setInterfaces] = useState(null); // null = sin cargar
  const [iface, setIface] = useState("");
  const [status, setStatus] = useState({ state: "idle", packets: 0, bytes: 0, seconds: 0, reason: null });
  const [loading, setLoading] = useState(false);
  const stopping = useRef(false);

  const running = status.state === "running";

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next && interfaces === null) {
      setLoading(true);
      try {
        const list = await api.interfaces();
        setInterfaces(list);
        if (list.length) setIface(list[0].name);
      } catch (e) {
        setInterfaces([]);
        onError(e.message);
      } finally {
        setLoading(false);
      }
    }
  }

  const stop = useCallback(async () => {
    if (stopping.current) return; // evita un doble stop si el sondeo y el clic coinciden
    stopping.current = true;
    try {
      const done = await api.liveStop();
      setStatus((s) => ({
        ...s,
        state: "finished",
        reason: done.capture.reason,
        warning: done.capture.warning ?? null,
      }));
      onAnalyzed(done.analysis);
    } catch (e) {
      onError(e.message);
    } finally {
      stopping.current = false;
    }
  }, [onAnalyzed, onError]);

  async function start() {
    try {
      setStatus(await api.liveStart({ interface: iface }));
    } catch (e) {
      onError(e.message); // p. ej. "ejecutá Tracewell como administrador"
    }
  }

  // Sondeo mientras corre. Si la captura termina sola (por un límite) pedimos
  // el análisis automáticamente en vez de dejar al usuario mirando un contador
  // congelado.
  useEffect(() => {
    if (!running) return undefined;
    const id = setInterval(async () => {
      try {
        const s = await api.liveStatus();
        setStatus(s);
        if (s.state === "finished") stop();
      } catch (e) {
        onError(e.message);
      }
    }, 1000);
    return () => clearInterval(id);
  }, [running, stop, onError]);

  return (
    <section className="card live" aria-labelledby="live-title">
      <div className="card-head">
        <h2 id="live-title">Captura en vivo</h2>
        <button type="button" className="link" onClick={toggle} aria-expanded={open}>
          {open ? "Ocultar" : "Mostrar"}
        </button>
      </div>
      {open && (
        <div className="live-body">
          <p className="muted">
            Requiere administrador/root (y Npcap en Windows). Los límites por defecto son 1.000.000 de
            paquetes y 10 minutos.
          </p>
          {loading && <p className="empty">Buscando interfaces…</p>}
          {interfaces && interfaces.length === 0 && !loading && (
            <p className="empty">No se encontraron interfaces.</p>
          )}
          {interfaces && interfaces.length > 0 && (
            <div className="live-controls">
              <label htmlFor="iface">Interfaz</label>
              <select id="iface" value={iface} onChange={(e) => setIface(e.target.value)} disabled={running}>
                {interfaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.description === i.name ? i.name : `${i.name} — ${i.description}`}
                  </option>
                ))}
              </select>
              {running ? (
                <button type="button" onClick={stop}>
                  Detener y analizar
                </button>
              ) : (
                <button type="button" onClick={start} disabled={disabled || !iface}>
                  Iniciar captura
                </button>
              )}
            </div>
          )}
          {(running || status.state === "finished") && (
            <p role="status" aria-live="polite" className="live-status">
              {running ? "Capturando… " : "Captura terminada. "}
              <strong>{status.packets.toLocaleString("es-AR")}</strong> paquetes ·{" "}
              {formatBytes(status.bytes)} · {status.seconds.toFixed(1)} s
              {!running && status.reason ? ` (${REASON[status.reason] ?? status.reason})` : ""}
            </p>
          )}
          {/* La captura se cerró, pero algo falló al detenerla (la fuente no
              respondió, error de escritura): se avisa en vez de aparentar éxito. */}
          {!running && status.state === "finished" && status.warning && (
            <p className="banner banner-warn" role="note">
              Atención: {status.warning}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
