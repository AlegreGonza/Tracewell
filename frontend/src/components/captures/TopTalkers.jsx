import { useEffect, useState } from "react";
import { IconTrendingUp } from "@tabler/icons-react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

const COLORS = ["var(--data-1)", "var(--data-2)", "var(--data-3)", "var(--data-4)", "var(--data-5)"];

// «Quién más habla»: los equipos con más tráfico, como barras de colores
export default function TopTalkers({ refreshKey, onError, onFilterIp }) {
  const [hosts, setHosts] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .hosts(ctl.signal)
      .then((h) => setHosts(h.items.slice(0, 5)))
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  if (!hosts || hosts.length === 0) return null;
  const max = Math.max(...hosts.map((h) => h.bytes), 1);

  return (
    <section className="card talkers" aria-labelledby="talkers-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="talkers-title"><IconTrendingUp size={16} aria-hidden="true" /> Quién más habla</h2>
          <HelpTip topic="equipos" />
        </div>
      </div>
      <ul className="talkers-list">
        {hosts.map((h, i) => (
          <li key={h.ip}>
            <button type="button" className="link mono" onClick={() => onFilterIp?.(h.ip)} title={h.name ?? h.owner ?? "Ver sus sesiones"}>
              {h.ip}
            </button>
            <span className="talkers-name muted">{h.name ?? h.owner ?? h.role_label ?? ""}</span>
            <span className="talkers-track" aria-hidden="true">
              <i style={{ width: `${Math.max(3, (h.bytes / max) * 100)}%`, background: COLORS[i % COLORS.length] }} />
            </span>
            <span className="talkers-val">{formatBytes(h.bytes)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
