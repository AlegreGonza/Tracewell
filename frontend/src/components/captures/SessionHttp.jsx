import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatBytes } from "../../lib/format.js";
import HelpTip from "../common/HelpTip.jsx";

// Notas en lenguaje simple de un intercambio HTTP: lo que merece una mirada. Siempre texto.
export function httpNotes(ex) {
  const notes = [];
  if (ex.sensitive_fields?.length) notes.push(`Envía un campo de contraseña SIN cifrar: ${ex.sensitive_fields.join(", ")}`);
  if (ex.auth?.scheme) notes.push(`Autenticación ${ex.auth.scheme}${ex.auth.user ? ` (usuario ${ex.auth.user})` : ""} sin cifrar`);
  if (ex.location) notes.push(`Redirige a ${ex.location}`);
  if (ex.complete === false) notes.push("Incompleto: faltan bytes en la captura");
  return notes;
}

const confirmDownload = (e) => {
  // Son datos de la red y pueden ser malware: se pide confirmación antes de bajar nada.
  if (!window.confirm("Este archivo salió de la captura y puede ser malware. Se guardará como .bin. No lo abras ni lo ejecutes. ¿Descargarlo?")) {
    e.preventDefault();
  }
};

export function FileCard({ file, href }) {
  return (
    <li className={file.risky ? "file risky" : "file"}>
      <p>
        <strong className="mono">{file.name}</strong> · {file.direction} · {formatBytes(file.size)}
        {file.risky && <span className="badge sev-high" title="Ejecutable o script: puede correr código si se abre">peligroso</span>}
        {!file.complete && <span className="badge sev-medium">incompleto</span>}
      </p>
      <p className="muted">Tipo real: {file.kind}{file.content_type ? ` (el servidor dijo: ${file.content_type})` : ""}</p>
      <p className="mono hash">SHA-256: {file.sha256}</p>
      <a className="button" href={href} download onClick={confirmDownload}>Guardar como .bin</a>
    </li>
  );
}

// Peticiones y respuestas HTTP (sin cifrar) de UNA sesión, y los archivos que viajaron. No se muestra si no hay HTTP.
export default function SessionHttp({ session, onError }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    setData(null);
    if (session.protocol !== "TCP") return undefined;
    const ctl = new AbortController();
    api
      .sessionHttp(session.id, ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [session.id, session.protocol, onError]);

  if (!data || data.exchanges.length === 0) return null;
  const files = data.exchanges.filter((ex) => ex.file);
  return (
    <section className="session-http" aria-labelledby="http-title">
      <h3 id="http-title">
        HTTP <HelpTip topic="http" />
      </h3>
      {data.incomplete && <p className="banner banner-warn" role="note">Faltan bytes en la captura: puede haber intercambios incompletos.</p>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Pedido</th>
              <th scope="col">Respuesta</th>
              <th scope="col">Notas</th>
            </tr>
          </thead>
          <tbody>
            {data.exchanges.map((ex) => (
              <tr key={ex.index}>
                <td className="mono">
                  <strong>{ex.method}</strong> {ex.host ?? ""}{ex.target}
                  {ex.user_agent && <div className="muted">{ex.user_agent}</div>}
                </td>
                <td className="mono">
                  {ex.status ?? "—"} {ex.reason ?? ""}
                  <div className="muted">{ex.response_type ?? ""} {ex.response_bytes ? `· ${formatBytes(ex.response_bytes)}` : ""}</div>
                </td>
                <td>
                  {httpNotes(ex).map((n) => (
                    <div key={n} className="note-chip">{n}</div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {files.length > 0 && (
        <>
          <h3>
            Archivos <HelpTip topic="archivos" />
          </h3>
          <ul className="files">
            {files.map((ex) => (
              <FileCard key={ex.index} file={ex.file} href={api.httpBodyUrl(session.id, ex.index)} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
