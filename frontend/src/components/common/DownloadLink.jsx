import { useState } from "react";
import { api } from "../../api/client.js";
import { getToken } from "../../api/token.js";

// Enlace de descarga. Un <a download> no puede mandar la cabecera del token: con token activo se
// pide un ticket de un solo uso (30 s) y se baja con la URL del ticket, sin cargar el archivo en memoria.
export default function DownloadLink({ href, download, className = "button", onClick, children }) {
  const [failed, setFailed] = useState(false);

  const handle = async (e) => {
    onClick?.(e); // p. ej. la confirmación de «puede ser malware»: si cancela, no se baja nada
    if (e.defaultPrevented || !getToken()) return; // sin token (desarrollo, tests): enlace normal
    e.preventDefault();
    setFailed(false);
    try {
      const a = document.createElement("a");
      a.href = await api.ticketUrl(href);
      a.download = typeof download === "string" ? download : "";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch {
      setFailed(true);
    }
  };

  return (
    <>
      <a className={className} href={href} download={download} onClick={handle}>
        {children}
      </a>
      {failed && <span role="alert" className="muted"> No se pudo preparar la descarga. Probá de nuevo.</span>}
    </>
  );
}
