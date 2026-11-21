import { DonutChart } from "@mantine/charts";
import { ThemeIcon } from "@mantine/core";
import { IconAlertTriangle, IconArrowsExchange, IconArrowsUpDown, IconCircleCheck, IconCircleDashed, IconPackage } from "@tabler/icons-react";
import { formatBytes, percent } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

const n = (v) => v.toLocaleString("es-AR");

// Color de cada protocolo en la dona y en las barras (colores de datos: la severidad conserva el suyo).
const PROTO_COLOR = { TCP: "var(--data-1)", UDP: "var(--data-2)", ICMP: "var(--data-3)", ICMPv6: "var(--data-3)" };
const colorOf = (proto) => PROTO_COLOR[proto] ?? "var(--data-n)";

const StatIcon = ({ icon: Icon, color }) => (
  <ThemeIcon className="stat-icon" variant="light" size="lg" radius="md" color={color} aria-hidden="true">
    <Icon size={20} stroke={1.8} />
  </ThemeIcon>
);

export default function Summary({ capture }) {
  const { stats } = capture;
  const rows = Object.entries(stats.by_protocol).sort((a, b) => b[1].packets - a[1].packets);

  return (
    <section className="card" aria-labelledby="summary-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="summary-title">Resumen</h2>
          <HelpTip topic="resumen" />
        </div>
        <span className="muted">
          {capture.source} · {capture.format}
          {capture.snaplen ? ` · snaplen ${capture.snaplen}` : ""}
        </span>
      </div>
      {/* Análisis parcial: sin este aviso el analista creería que las cifras
          cubren toda la captura, y un escaneo grande podría ocultarse. */}
      {stats.truncated && (
        <p className="banner banner-warn" role="note">
          Análisis parcial: se alcanzó el tope de sesiones y se descartaron{" "}
          {n(stats.untracked_packets ?? 0)} paquetes de sesiones nuevas. Las cifras de abajo no
          incluyen ese tráfico.
        </p>
      )}
      <dl className="stats">
        <div className="stat stat-sessions"><StatIcon icon={IconArrowsExchange} color="tw" /><dt>Sesiones</dt><dd>{n(stats.sessions)}</dd></div>
        <div className="stat stat-packets"><StatIcon icon={IconPackage} color="teal" /><dt>Paquetes</dt><dd>{n(stats.packets)}</dd></div>
        <div className="stat stat-bytes"><StatIcon icon={IconArrowsUpDown} color="violet" /><dt>Tráfico</dt><dd>{formatBytes(stats.bytes)}</dd></div>
        <div className={`stat stat-alerts${capture.alerts > 0 ? " has-alerts" : ""}`}><StatIcon icon={capture.alerts > 0 ? IconAlertTriangle : IconCircleCheck} color={capture.alerts > 0 ? "orange" : "teal"} /><dt>Alertas</dt><dd>{n(capture.alerts)}</dd></div>
        {/* Se muestran siempre: el total de sesiones no incluye estos paquetes
            y ocultarlos le haría creer al analista que vio todo. */}
        <div className="stat stat-minor"><StatIcon icon={IconCircleDashed} color="gray" /><dt>Sin IP (ARP…)</dt><dd>{n(stats.non_ip)}</dd></div>
        <div className="stat stat-minor"><StatIcon icon={IconCircleDashed} color="gray" /><dt>Dañados</dt><dd>{n(stats.malformed)}</dd></div>
      </dl>
      <h3>Distribución por protocolo</h3>
      {rows.length === 0 ? (
        <p className="muted">Sin sesiones.</p>
      ) : (
        <div className="proto-chart">
        <div className="donut" aria-hidden="true">
          <DonutChart
            size={150}
            thickness={24}
            withTooltip
            tooltipDataSource="segment"
            data={rows.map(([proto, st]) => ({ name: proto, value: st.packets, color: colorOf(proto) }))}
          />
        </div>
        <ul className="bars">
          {rows.map(([proto, s]) => {
            const pct = percent(s.packets, stats.packets);
            return (
              <li key={proto} style={{ "--c": colorOf(proto) }}>
                <span className="bar-label">{proto}</span>
                <span className="bar-track" aria-hidden="true">
                  <span className="bar-fill" style={{ width: `${pct}%` }} />
                </span>
                <span className="bar-value">
                  {n(s.packets)} paq. · {pct}% · {formatBytes(s.bytes)}
                </span>
              </li>
            );
          })}
        </ul>
        </div>
      )}
    </section>
  );
}
