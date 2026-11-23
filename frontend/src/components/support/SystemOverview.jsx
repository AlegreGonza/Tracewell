import { api } from "../../api/client.js";
import { formatBytes, formatDuration } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";
import RefreshButton from "./RefreshButton.jsx";
import { useLoad } from "../../controllers/useLoad.js";

// Una barra con el porcentaje en texto (el color solo refuerza: el número siempre está)
export function Meter({ label, percent, detail, goodHigh = false }) {
  const p = Number.isFinite(percent) ? Math.max(0, Math.min(100, percent)) : 0;
  const level = goodHigh ? (p < 40 ? "high" : p < 70 ? "mid" : "ok") : p >= 90 ? "high" : p >= 75 ? "mid" : "ok";
  return (
    <div className="meter-row">
      <div className="meter-label">
        <span>{label}</span>
        <span className="mono">{Number.isFinite(percent) ? `${p.toFixed(1)} %` : "—"}</span>
      </div>
      <div className={`meter meter-${level}`} role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={p}>
        <div style={{ width: `${p}%` }} />
      </div>
      {detail && <div className="muted meter-detail">{detail}</div>}
    </div>
  );
}

export default function SystemOverview({ active }) {
  const { data, error, loading, reload, updatedAt } = useLoad((s) => api.systemOverview(s), { every: 5000, active });

  if (error) return <p className="banner banner-error" role="alert">{error}</p>;
  if (!data) return <p className="muted pad">{loading ? "Leyendo el equipo…" : "—"}</p>;
  const { memory, swap, disks, battery, network_total: net } = data;

  return (
    <section className="card" aria-labelledby="sysov-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="sysov-title">Resumen del equipo</h2>
          <HelpTip topic="sistema_resumen" />
        </div>
        <RefreshButton link onClick={reload} loading={loading} updatedAt={updatedAt} />
      </div>
      <div className="sys-grid">
        <Meter label="Memoria (RAM)" percent={memory.percent} detail={`${formatBytes(memory.used)} usados de ${formatBytes(memory.total)} · ${formatBytes(memory.available)} libres`} />
        <Meter label="Procesador" percent={data.cpu_percent} detail={`${data.cpu_count} hilos (${data.cpu_physical ?? "?"} núcleos físicos)`} />
        {swap && <Meter label="Memoria virtual (archivo de paginación)" percent={swap.percent} detail={`${formatBytes(swap.used)} de ${formatBytes(swap.total)}`} />}
        {disks.map((d) => (
          <Meter key={d.mount} label={`Disco ${d.mount}`} percent={d.percent} detail={`${formatBytes(d.used)} de ${formatBytes(d.total)} · ${d.fstype}`} />
        ))}
      </div>
      <dl className="facts">
        <div><dt>Encendida hace</dt><dd>{data.uptime_seconds != null ? formatDuration(data.uptime_seconds) : "—"}</dd></div>
        <div><dt>Procesos en marcha</dt><dd>{data.process_count}</dd></div>
        {net && <div><dt>Red desde el arranque</dt><dd>{formatBytes(net.received)} recibidos · {formatBytes(net.sent)} enviados</dd></div>}
        {battery && <div><dt>Batería</dt><dd>{battery.percent} % {battery.plugged ? "(enchufada)" : "(con batería)"}</dd></div>}
      </dl>
    </section>
  );
}
