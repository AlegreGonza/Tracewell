import { Component } from "react";

// Un error al RENDERIZAR (un dato inesperado de la API, un bug) desmonta todo el
// árbol de React y deja la pantalla en blanco. Un Error Boundary lo atrapa y
// muestra un aviso. Tiene que ser una clase: React no ofrece equivalente con
// hooks. No atrapa errores de eventos ni de código asíncrono: esos se manejan con
// try/catch en cada handler. Ver react.dev/reference/react/Component
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
