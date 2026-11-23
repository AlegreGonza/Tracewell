import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatDuration, formatTime } from "../../lib/format.js";
import { BarChart } from "@mantine/charts";
import HelpTip from "../common/HelpTip.jsx";

// Gráfico de barras del tráfico en el tiempo (SVG, sin librerías)
export default function Timeline({ refreshKey, onError }) {
  const [data, setData] = useState(null);
  const [metric, setMetric] = useState("packets");

  useEffect(() => {
    const ctl = new AbortController();
    api
      .timeline(ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [refreshKey, onError]);

  if (!data || !data.packets || data.packets.length === 0) return null;

  // Si la respuesta viniera mal formada (otra longitud)
  const chosen = data[metric];
  const values = Array.isArray(chosen) && chosen.length === data.packets.length ? chosen : data.packets;
  const peak = values.indexOf(Math.max(...values));
  const unit = metric === "bytes" ? "bytes" : "paquetes";
  const at = (i) => formatTime(data.start + i * data.bucket_seconds);
  const summary = `Tráfico en el tiempo: ${values.length} intervalos de ${formatDuration(data.bucket_seconds)}. Pico de ${values[peak].toLocaleString("es-AR")} ${unit} a las ${at(peak)}.`;

  return (
    <section className="card" aria-labelledby="timeline-title">
      <div className="card-head">
        <div className="head-title">
          <h2 id="timeline-title">Tráfico en el tiempo</h2>
          <HelpTip topic="tiempo" />
        </div>
        <label className="inline">
          Mostrar
          <select value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="packets">Paquetes</option>
            <option value="bytes">Bytes</option>
          </select>
        </label>
      </div>
      <div className="timeline">
        <div className="timeline-plot" role="img" aria-label={summary}>
          <BarChart
            h={170}
            data={values.map((v, i) => ({ time: at(i).slice(0, 8), value: v }))}
            dataKey="time"
            series={[{ name: "value", label: unit === "bytes" ? "Bytes" : "Paquetes", color: "tw.5" }]}
            getBarColor={(v) => (v === values[peak] ? "orange.5" : "tw.5")}
            valueFormatter={(v) => `${v.toLocaleString("es-AR")} ${unit}`}
            xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
            tickLine="y"
            gridAxis="y"
            withLegend={false}
          />
        </div>
        <p className="timeline-axis mono muted">
          <span>{at(0)}</span>
          <span>cada barra = {formatDuration(data.bucket_seconds)}</span>
          <span>{at(values.length - 1)}</span>
        </p>
        <p className="muted">{summary}</p>
      </div>
    </section>
  );
}
