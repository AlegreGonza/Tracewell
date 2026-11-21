import { useEffect, useState } from "react";
import { IconShieldHalf } from "@tabler/icons-react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";

// Peso de cada alerta en el puntaje, por severidad. El puntaje es la SUMA de los pesos (tope 100): se muestra el porqué.
export const RISK_WEIGHT = { critical: 35, high: 25, medium: 12, low: 5 };
const SHAPE = { critical: "◆", high: "▲", medium: "●", low: "▼" };
const LABEL = { critical: "crítica", high: "alta", medium: "media", low: "baja" };
const ORDER = ["critical", "high", "medium", "low"];

export function riskScore(alerts) {
  const sum = alerts.reduce((acc, a) => acc + (RISK_WEIGHT[a.severity] ?? 5), 0);
  return Math.min(100, sum);
}

export function riskLevel(score) {
  if (score >= 70) return { id: "alto", text: "Alto", color: "var(--sev-critical)" };
  if (score >= 40) return { id: "medio", text: "Medio", color: "var(--sev-high)" };
  if (score > 0) return { id: "bajo", text: "Bajo", color: "var(--sev-medium)" };
  return { id: "nulo", text: "Sin alertas", color: "var(--ok)" };
}

// Medio círculo: el arco de color llega hasta el puntaje (0–100).
function Gauge({ score, color }) {
  const a = Math.PI * (1 - score / 100);
  const x = 60 + 50 * Math.cos(a);
  const y = 60 - 50 * Math.sin(a);
  return (
    <svg className="gauge" viewBox="0 0 120 70" aria-hidden="true">
      <path d="M10 60 A50 50 0 0 1 110 60" fill="none" className="gauge-base" strokeWidth="10" strokeLinecap="round" />
      {score > 0 && <path d={`M10 60 A50 50 0 0 1 ${x} ${y}`} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" />}
    </svg>
  );
}

// «Puntaje de riesgo»: un número de 0 a 100 que resume las alertas, con la lista de motivos (nada de cajas negras).
export default function RiskCard({ refreshKey, onError }) {
  const [alerts, setAlerts] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .alerts(undefined, ctl.signal)
      .then((d) => setAlerts(Array.isArray(d) ? d : d?.items ?? []))
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  if (!alerts) return null;
  const score = riskScore(alerts);
  const level = riskLevel(score);
  const sorted = [...alerts].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));

  return (
    <section className="card risk-card" aria-labelledby="risk-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="risk-title"><IconShieldHalf size={16} aria-hidden="true" /> Puntaje de riesgo</h2>
          <HelpTip topic="riesgo" />
        </div>
      </div>
      <div className="risk-body">
        <div className="risk-gauge" style={{ "--c": level.color }}>
          <Gauge score={score} color={level.color} />
          <strong className="risk-num">{score}</strong>
          <span className="risk-level">{level.text}</span>
        </div>
        <ul className="risk-why" aria-label="Por qué este puntaje">
          {sorted.slice(0, 5).map((a, i) => (
            <li key={`${a.rule_id}-${i}`} className={`sev-${a.severity}`}>
              <span className="risk-shape" aria-hidden="true">{SHAPE[a.severity] ?? "●"}</span>
              <span>{a.name}</span>
              <span className="muted mono">+{RISK_WEIGHT[a.severity] ?? 5} · {LABEL[a.severity] ?? a.severity}</span>
            </li>
          ))}
          {sorted.length === 0 && <li className="muted">Sin alertas: no hay nada que sumar.</li>}
        </ul>
      </div>
    </section>
  );
}
