import { StrictMode } from 'react'
import ReactDOM from 'react-dom/client'
import { initToken } from '@/lib/api/token'
import { createQueryClient } from '@/lib/query-client'
import { App } from './app'
import { createAppRouter } from './router'
// Estilos
import './styles/index.css'

// El token (#token=... o ventana de escritorio) se lee y se limpia ANTES de crear el router:
// el router usa la URL y, si arrancara primero, el token quedaría en el historial.
async function bootstrap() {
  await initToken()
  const queryClient = createQueryClient()
  const router = createAppRouter(queryClient)
  const rootElement = document.getElementById('root')!
  if (rootElement.innerHTML) return
  ReactDOM.createRoot(rootElement).render(
    <StrictMode>
      <App queryClient={queryClient} router={router} />
    </StrictMode>
  )
}

void bootstrap()
