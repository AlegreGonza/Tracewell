import { useId, useState } from "react";
import { HELP } from "../../lib/help.js";

// Botón «?» que despliega una explicación en lenguaje simple.
// El contenido sale de help.js: texto fijo, nunca datos de la captura.
export default function HelpTip({ topic }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const help = Object.hasOwn(HELP, topic) ? HELP[topic] : null; // hasOwn: un tema como "constructor" no existe
  if (!help) return null;
  return (
    <span className="helptip">
      <button
        type="button"
        className="help-btn"
        aria-expanded={open}
        aria-controls={id}
        aria-label={`Ayuda: ${help.title}`}
        title="¿Qué estoy viendo?"
        onClick={() => setOpen((v) => !v)}
      >
        ?
      </button>
      {open && (
        <div id={id} role="note" className="help-body">
          <p>{help.text}</p>
        </div>
      )}
    </span>
  );
}
