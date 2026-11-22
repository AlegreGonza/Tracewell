import { useState } from "react";

// Botón «Copiar filtro Wireshark». El filtro llega ya armado (`filter`) o se pide al hacer clic (`load`).
// Si el portapapeles no está disponible, el filtro queda a la vista para copiarlo a mano.
// El filtro puede incluir texto del tráfico (nombres DNS): se muestra siempre como texto, nunca como HTML.
export default function CopyFilterButton({ filter, load, onError, label = "Copiar filtro Wireshark" }) {
  const [text, setText] = useState(null);
  const [copied, setCopied] = useState(false);

  async function copy() {
    setCopied(false);
    let value = filter;
    try {
      value = value ?? (await load?.());
    } catch (e) {
      onError?.(e.message);
      return;
    }
    if (!value) {
      onError?.("No hay un filtro de Wireshark para esto.");
      return;
    }
    setText(value);
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      /* sin permiso para el portapapeles: el filtro queda visible para copiarlo a mano */
    }
  }

  return (
    <span className="copy-filter">
      <button type="button" onClick={copy}>
        {label}
      </button>
      {text && (
        <>
          <code className="mono copy-filter-text">{text}</code>
          <span role="status" className="muted">
            {copied ? "Copiado" : "No se pudo copiar solo: seleccionalo y copialo"}
          </span>
        </>
      )}
    </span>
  );
}
