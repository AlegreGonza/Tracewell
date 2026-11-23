import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import { HINT_LABEL } from "./hints.js";
import { useLoad } from "../../controllers/useLoad.js";

const when = (epoch) => (Number.isFinite(epoch) ? new Date(epoch * 1000).toLocaleString("es-AR") : "—");

// Detalle de UN proceso
export default function ProcessDetail({ pid, onClose, onSelect }) {
  const { data, error, loading } = useLoad((s) => api.systemProcess(pid, s), { deps: [pid] });
  const [file, setFile] = useState(null);
  const [fileError, setFileError] = useState(null);
  const [fileBusy, setFileBusy] = useState(false);

  useEffect(() => {
    setFile(null);
    setFileError(null);
  }, [pid]);

  async function loadFile() {
    setFileBusy(true);
    setFileError(null);
    try {
      setFile(await api.systemProcessFile(pid));
    } catch (e) {
      setFileError(e.message);
    } finally {
      setFileBusy(false);
    }
  }

  return (
    <aside className="detail" aria-label={`Proceso ${pid}`}>
      <div className="card-head">
        <h2>Proceso {pid}</h2>
        <button type="button" className="link" onClick={onClose}>Cerrar</button>
      </div>
      {error && <p className="banner banner-error" role="alert">{error}</p>}
      {!data && !error && <p className="muted pad">{loading ? "Leyendo…" : "—"}</p>}
      {data && (
        <div className="proc-detail">
          <p className="mono big">{data.name ?? "—"}</p>
          {data.hints.map((h) => (
            <p key={h.code} className="banner banner-warn" role="note"><strong>{HINT_LABEL[h.code] ?? h.code}.</strong> {h.text}</p>
          ))}
          <dl className="facts">
            <div><dt>Programa</dt><dd className="mono break">{data.exe ?? "— (sin permiso para verlo)"}</dd></div>
            <div><dt>Línea de comandos</dt><dd className="mono break">{data.cmdline ?? "—"}</dd></div>
            <div><dt>Carpeta de trabajo</dt><dd className="mono break">{data.cwd ?? "—"}</dd></div>
            <div><dt>Usuario</dt><dd className="mono">{data.user ?? "—"}</dd></div>
            <div><dt>Arrancó</dt><dd>{when(data.started)}</dd></div>
            <div><dt>Estado</dt><dd>{data.status ?? "—"} · {data.threads ?? "—"} hilos</dd></div>
            <div><dt>Memoria</dt><dd>{data.rss != null ? `${formatBytes(data.rss)} en uso` : "—"}{data.vms != null ? ` · ${formatBytes(data.vms)} reservados` : ""}</dd></div>
            {data.io && <div><dt>Disco leído / escrito</dt><dd>{formatBytes(data.io.read)} / {formatBytes(data.io.written)}</dd></div>}
            <div>
              <dt>Lo lanzó</dt>
              <dd>
                {data.parent ? (
                  <button type="button" className="link mono" onClick={() => onSelect(data.parent.pid)}>
                    {data.parent.name ?? "?"} ({data.parent.pid})
                  </button>
                ) : (
                  "— (ya no existe o no se puede ver)"
                )}
              </dd>
            </div>
            {data.children.length > 0 && (
              <div>
                <dt>Lanzó a</dt>
                <dd>
                  {data.children.map((c) => (
                    <button key={c.pid} type="button" className="link mono" onClick={() => onSelect(c.pid)}>
                      {c.name ?? "?"} ({c.pid}){" "}
                    </button>
                  ))}
                </dd>
              </div>
            )}
          </dl>

          <div className="file-check">
            <button type="button" onClick={loadFile} disabled={fileBusy}>
              {fileBusy ? "Verificando…" : "Ver huella y firma del archivo"}
            </button>
            <span className="muted"> Solo lee el archivo del disco; no lo envía a ningún lado.</span>
            {fileError && <p className="banner banner-error" role="alert">{fileError}</p>}
            {file && !file.available && <p className="muted">{file.reason}</p>}
            {file?.available && (
              <dl className="facts">
                <div><dt>Tamaño</dt><dd>{file.size != null ? formatBytes(file.size) : "—"}</dd></div>
                <div>
                  <dt>SHA-256</dt>
                  <dd className="mono break">{file.sha256 ?? file.hash_note ?? "—"}</dd>
                </div>
                <div>
                  <dt>Firma digital</dt>
                  <dd>
                    {file.signature?.text ?? "—"}
                    {file.signature?.subject && <div className="mono muted break">{file.signature.subject}</div>}
                  </dd>
                </div>
              </dl>
            )}
          </div>

          <h3>Conexiones ({data.connections.length})</h3>
          {data.connections.length === 0 ? (
            <p className="muted pad-s">Sin conexiones de red abiertas (o no se pueden ver).</p>
          ) : (
            <ul className="plain-list mono">
              {data.connections.map((c, i) => (
                <li key={`${c.local}-${c.remote}-${i}`}>
                  {c.local} {c.remote ? `→ ${c.remote}` : "(escuchando)"} · {c.status}
                  {c.owner ? ` · ${c.owner}` : ""}
                </li>
              ))}
            </ul>
          )}

          {data.modules.length > 0 && (
            <details>
              <summary>Bibliotecas cargadas ({data.modules.length})</summary>
              <ul className="plain-list mono small">{data.modules.map((m) => <li key={m} className="break">{m}</li>)}</ul>
            </details>
          )}
          {data.open_files.length > 0 && (
            <details>
              <summary>Archivos abiertos ({data.open_files.length})</summary>
              <ul className="plain-list mono small">{data.open_files.map((f) => <li key={f} className="break">{f}</li>)}</ul>
            </details>
          )}
        </div>
      )}
    </aside>
  );
}
