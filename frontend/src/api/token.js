// Token de la API: lo genera main.py en cada arranque y lo entrega a la ventana o a la URL.
const KEY = "tracewell-token";
const WAIT_MS = 2000; // cuánto esperamos a la ventana de escritorio antes de seguir sin token

let token = null;

export function getToken() {
  return token;
}

function fromHash() {
  const m = /[#&]token=([^&]+)/.exec(window.location.hash);
  if (!m) return null;
  // Se saca de la barra de direcciones: no queda en el historial ni se copia por error.
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
  return decodeURIComponent(m[1]);
}

function fromDesktop() {
  return new Promise((resolve) => {
    const ask = () => {
      const api = window.pywebview?.api;
      if (typeof api?.get_token !== "function") return resolve(null);
      api.get_token().then(resolve, () => resolve(null));
    };
    if (window.pywebview?.api) return ask();
    window.addEventListener("pywebviewready", ask, { once: true });
    setTimeout(() => resolve(null), WAIT_MS);
  });
}

// Se llama una vez antes de dibujar la interfaz: #token= (navegador) o la ventana de escritorio.
export async function initToken() {
  token = fromHash() ?? window.sessionStorage.getItem(KEY) ?? (await fromDesktop());
  if (token) window.sessionStorage.setItem(KEY, token);
  return token;
}
