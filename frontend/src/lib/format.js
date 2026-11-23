// Formateadores puros (sin React): fáciles de probar y reutilizables.

export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  const fmt = (x) => x.toFixed(x < 10 ? 2 : 1);
  let v = n / 1024;
  let i = 0;
  // Se compara el valor YA redondeado
  while (Number(fmt(v)) >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${fmt(v)} ${units[i]}`;
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 1) {
    const ms = Math.round(seconds * 1000);
    if (ms < 1000) return `${ms} ms`; // 0,9996 s redondea a 1000 ms: sigue como segundos
  }
  if (seconds < 59.995) return `${seconds.toFixed(2)} s`; // 59,999 s no debe verse "60.00 s"
  const total = Math.round(seconds);
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m < 60) return `${m} min ${s} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

// Epoch en segundos -> "HH:MM:SS.mmm" en UTC
export function formatTime(epoch) {
  if (!Number.isFinite(epoch)) return "—";
  return new Date(epoch * 1000).toISOString().slice(11, 23) + " UTC";
}

export function formatEndpoint(ip, port) {
  if (!ip) return "—";
  const host = ip.includes(":") ? `[${ip}]` : ip; // IPv6 lleva corchetes si hay puerto
  return port === null || port === undefined ? ip : `${host}:${port}`;
}

export const SEVERITY_LABEL = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

export function severityLabel(s) {
  return SEVERITY_LABEL[s] ?? String(s);
}

// Porcentaje para las barras de distribución; protege contra total 0.
export function percent(part, total) {
  if (!total || total <= 0) return 0;
  return Math.round((part / total) * 1000) / 10;
}
