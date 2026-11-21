import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";

// Las 14 tácticas de MITRE ATT&CK (Enterprise), en el orden del ciclo de un ataque, con una frase simple cada una.
export const TACTICS = [
  ["Reconnaissance", "Reconocimiento", "Investigan a la víctima antes de atacar."],
  ["Resource Development", "Preparación", "Arman la infraestructura y las herramientas."],
  ["Initial Access", "Acceso inicial", "Consiguen entrar."],
  ["Execution", "Ejecución", "Corren su código en el equipo."],
  ["Persistence", "Persistencia", "Se aseguran de seguir adentro."],
  ["Privilege Escalation", "Más privilegios", "Buscan permisos de administrador."],
  ["Defense Evasion", "Evadir defensas", "Se esconden de antivirus y monitoreo."],
  ["Credential Access", "Robo de credenciales", "Roban usuarios y contraseñas."],
  ["Discovery", "Exploración", "Miran qué hay en la red."],
  ["Lateral Movement", "Movimiento lateral", "Saltan a otros equipos."],
  ["Collection", "Recolección", "Juntan los datos que quieren."],
  ["Command and Control", "Comando y control", "Reciben órdenes desde afuera."],
  ["Exfiltration", "Exfiltración", "Sacan los datos de la red."],
  ["Impact", "Impacto", "Dañan o interrumpen sistemas."],
];

const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

// Agrupa las alertas por táctica y técnica: { táctica: { técnica: {id, name, count, severity} } }.
export function groupByTactic(alerts) {
  const out = {};
  for (const a of alerts) {
    const tactic = (out[a.mitre_tactic] ??= {});
    const t = (tactic[a.mitre_technique] ??= { id: a.mitre_technique, name: a.mitre_name, count: 0, severity: a.severity });
    t.count += 1;
    if ((SEV_RANK[a.severity] ?? 0) > (SEV_RANK[t.severity] ?? 0)) t.severity = a.severity;
  }
  return out;
}

// Mapa MITRE ATT&CK de la captura: las tácticas que dispararon alertas se iluminan. Es un MARCO para ordenar lo hallado.
export default function AttackMap({ refreshKey, onError }) {
  const [alerts, setAlerts] = useState(null);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .alerts(undefined, ctl.signal)
      .then(setAlerts)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  if (alerts === null) return null;
  const grouped = groupByTactic(alerts);
  const known = new Set(TACTICS.map(([name]) => name));
  const extra = Object.keys(grouped).filter((t) => !known.has(t)); // una táctica que no esté en la lista no se pierde
  const columns = [...TACTICS, ...extra.map((t) => [t, t, ""])];

  return (
    <section className="card" aria-labelledby="attack-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="attack-title">Mapa MITRE ATT&amp;CK</h2>
          <HelpTip topic="attack" />
        </div>
      </div>
      <div className="attack-wrap">
        <ol className="attack-map">
          {columns.map(([name, label, gloss]) => {
            const techniques = Object.values(grouped[name] ?? {});
            return (
              <li key={name} className={techniques.length ? "tactic hit" : "tactic"} title={gloss || undefined}>
                <span className="tactic-name">{label}</span>
                <span className="tactic-en muted">{name}</span>
                {techniques.length === 0 ? (
                  <span className="tactic-none muted">—</span>
                ) : (
                  <ul>
                    {techniques.map((t) => (
                      <li key={t.id}>
                        <a
                          href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={`${t.name} · ${t.count} alerta(s)`}
                        >
                          {t.id}
                        </a>{" "}
                        <span className="muted">{t.name} ×{t.count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
        </ol>
      </div>
      <p className="muted attack-foot">
        {alerts.length === 0
          ? "Sin alertas: ninguna táctica se iluminó."
          : `${Object.keys(grouped).length} táctica(s) con actividad. Las columnas vacías no significan que no haya pasado nada: solo que ninguna regla lo vio.`}
      </p>
    </section>
  );
}
