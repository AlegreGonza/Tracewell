// role="alert": los lectores de pantalla anuncian el error apenas aparece.
export default function ErrorBanner({ error, onClose }) {
  if (!error) return null;
  return (
    <div className="banner banner-error" role="alert">
      <span>{error}</span>
      <button type="button" className="link" onClick={onClose} aria-label="Cerrar aviso">
        Cerrar
      </button>
    </div>
  );
}
