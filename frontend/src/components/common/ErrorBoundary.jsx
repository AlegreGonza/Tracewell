import { Component } from "react";

// Un error al RENDERIZAR
export default class ErrorBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error, info) {
    // Solo a la consola: la pantalla no muestra trazas ni rutas.
    console.error("Error de renderizado en la interfaz:", error, info?.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div role="alert" className="card welcome">
        <div className="welcome-body">
          <h2>Algo salió mal en la interfaz</h2>
          <p>Ocurrió un error inesperado. Recargá la página para volver a empezar.</p>
          <button type="button" onClick={() => window.location.reload()}>
            Recargar
          </button>
        </div>
      </div>
    );
  }
}
