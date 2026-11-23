import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import HelpTip from "../common/HelpTip.jsx";

const VERSIONS = { 13: "TLS 1.3", 12: "TLS 1.2", 11: "TLS 1.1", 10: "TLS 1.0", s3: "SSL 3.0", s2: "SSL 2.0" };
const ALPNS = { h2: "HTTP/2", h1: "HTTP/1.1", "00": "sin protocolo de aplicación (ALPN)" };

// Traduce la primera parte de una huella JA4 («t13d1516h2») a frases
export function describeJa4(ja4) {
  const a = String(ja4 ?? "").split("_")[0];
  if (a.length !== 10) return [];
  return [
    `${a[0] === "q" ? "QUIC" : "TCP"}`,
    VERSIONS[a.slice(1, 3)] ?? `versión ${a.slice(1, 3)}`,
    a[3] === "d" ? "pide un sitio por nombre (SNI)" : "no manda nombre de sitio",
    `${Number(a.slice(4, 6))} cifrados ofrecidos`,
    `${Number(a.slice(6, 8))} extensiones`,
    ALPNS[a.slice(8, 10)] ?? `ALPN ${a.slice(8, 10)}`,
  ];
}

const day = (iso) => (iso ? iso.slice(0, 10) : "—");

function Certificate({ cert }) {
  return (
    <div className="file">
      <p>
        <strong className="mono">{cert.subject ?? "(sin nombre)"}</strong>
        {cert.self_signed && <span className="badge sev-medium" title="El certificado lo firmó el mismo que lo presenta">autofirmado</span>}
        {cert.expired === true && <span className="badge sev-high" title="Estaba vencido en el momento de la captura">vencido</span>}
        {cert.not_yet_valid === true && <span className="badge sev-high">todavía no válido</span>}
      </p>
      <p className="muted">Emitido por: <span className="mono">{cert.issuer ?? "—"}</span></p>
      <p className="muted">Válido de {day(cert.not_before)} a {day(cert.not_after)}</p>
      {cert.names?.length > 0 && <p className="muted mono">Nombres: {cert.names.join(", ")}</p>}
      <p className="mono hash">SHA-256: {cert.sha256}</p>
    </div>
  );
}

// Lo que se ve de una sesión TLS sin descifrarla
export default function TlsView({ session, onError }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    setData(null);
    if (session.protocol !== "TCP") return undefined;
    const ctl = new AbortController();
    api
      .sessionTls(session.id, ctl.signal)
      .then(setData)
      .catch((e) => e.name !== "AbortError" && onError(e.message));
    return () => ctl.abort();
  }, [session.id, session.protocol, onError]);

  if (!data || !data.tls) return null;
  const { client, server, certificate } = data;
  const parts = describeJa4(client.ja4);

  return (
    <section className="tls" aria-labelledby="tls-title">
      <h3 id="tls-title">
        TLS (cifrado) <HelpTip topic="tls" />
      </h3>
      <dl className="tls-list">
        <div><dt>Sitio pedido (SNI)</dt><dd className="mono">{client.sni ?? "—"}</dd></div>
        <div><dt>Versión acordada</dt><dd>{server.version ?? "— (no se ve la respuesta del servidor)"}</dd></div>
        {server.cipher && <div><dt>Cifrado</dt><dd className="mono">{server.cipher}</dd></div>}
        <div>
          <dt>Huella JA4 <HelpTip topic="ja4" /></dt>
          <dd>
            {client.ja4 ? (
              <>
                <span className="mono hash">{client.ja4}</span>
                {parts.length > 0 && <p className="muted">Se lee así: {parts.join(" · ")}.</p>}
              </>
            ) : (
              <span className="muted">No se puede calcular: el saludo del cliente está incompleto (faltan bytes en la captura).</span>
            )}
          </dd>
        </div>
      </dl>
      {data.certificate_hidden && (
        <p className="banner banner-warn" role="note">
          En TLS 1.3 el certificado del servidor va cifrado: no se puede ver. Es normal y no indica nada raro.
        </p>
      )}
      {certificate && <Certificate cert={certificate} />}
      {!certificate && !data.certificate_hidden && (
        <p className="muted tls-note">No se ve el certificado en esta sesión (la captura puede haber empezado después del saludo).</p>
      )}
    </section>
  );
}
