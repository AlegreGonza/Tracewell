// Botón «Actualizar» con comprobante: muestra la hora de la última lectura (así se nota aunque los datos no hayan
// cambiado) y «Actualizando…» mientras trabaja.
export default function RefreshButton({ onClick, loading, updatedAt, link = false }) {
  return (
    <span className="refresh">
      <span className="muted refresh-status" role="status" aria-live="polite">
        {loading ? "Actualizando…" : updatedAt ? `Actualizado ${updatedAt.toLocaleTimeString("es-AR")}` : ""}
      </span>
      <button type="button" className={link ? "link" : undefined} onClick={onClick} disabled={loading}>
        Actualizar
      </button>
    </span>
  );
}
