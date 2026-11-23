import { useEffect, useState } from "react";
import { api } from "../../api/client.js";

const findPicker = () => window.pywebview?.api?.pick_file ?? null;

// Dentro de la ventana de escritorio pywebview expone un diálogo nativo para elegir archivo
function useNativePicker() {
  const [picker, setPicker] = useState(findPicker);
  useEffect(() => {
    const sync = () => setPicker(() => findPicker()); // () => f: guardar la función, no llamarla
    window.addEventListener("pywebviewready", sync);
    return () => window.removeEventListener("pywebviewready", sync);
  }, []);
  return picker;
}

// `onClose` + `closeLabel`
export default function Toolbar({
  busy, loaded, filters, onDemo, onAnalyze, onError, onClose, closeLabel = "Cerrar captura", onGlossary,
}) {
  const [path, setPath] = useState("");
  const pickFile = useNativePicker();

  async function browse() {
    try {
      const picked = await pickFile();
      if (picked) {
        setPath(picked);
        onAnalyze(picked);
      }
    } catch (e) {
      // Un diálogo nativo que falla no debe quedar como un rechazo sin manejar
      onError?.(e?.message || "No se pudo abrir el selector de archivos.");
    }
  }

  function submit(e) {
    e.preventDefault();
    if (path.trim()) onAnalyze(path.trim());
  }

  return (
    <header className="toolbar">
      <h1 className="brand">
        <svg className="brand-mark" viewBox="0 0 20 14" aria-hidden="true" focusable="false">
          <path d="M0 7h5l2.5-6 4 12L14 7h6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="miter" />
        </svg>
        Tracewell
      </h1>
      <form className="toolbar-form" onSubmit={submit}>
        <label className="sr-only" htmlFor="path">
          Ruta del archivo .pcap o .pcapng
        </label>
        <input
          id="path"
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="Ruta de un archivo .pcap / .pcapng"
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
        />
        {pickFile && (
          <button type="button" onClick={browse} disabled={busy}>
            Examinar…
          </button>
        )}
        <button type="submit" disabled={busy || !path.trim()}>
          Analizar
        </button>
      </form>
      <div className="toolbar-actions">
        <button type="button" onClick={onDemo} disabled={busy}>
          Modo demo
        </button>
        {onGlossary && (
          <button type="button" onClick={onGlossary}>
            Glosario
          </button>
        )}
        {loaded && onClose && (
          <button type="button" onClick={onClose} disabled={busy}>
            {closeLabel}
          </button>
        )}
        {/* Descarga directa del servidor; los filtros activos viajan en la URL
            para exportar exactamente lo que el analista está viendo. */}
        {loaded ? (
          <a className="button" href={api.exportUrl(filters)} download="tracewell-report.json">
            Exportar JSON
          </a>
        ) : (
          <span className="button disabled" aria-disabled="true">
            Exportar JSON
          </span>
        )}
        {/* Informe de triaje listo para un ticket */}
        {loaded ? (
          <a className="button" href={api.reportUrl()} download="tracewell-informe.html">
            Informe HTML
          </a>
        ) : (
          <span className="button disabled" aria-disabled="true">
            Informe HTML
          </span>
        )}
      </div>
    </header>
  );
}
