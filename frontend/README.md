# Tracewell · interfaz (frontend)

Interfaz nueva de Tracewell sobre la plantilla MIT [satnaing/shadcn-admin](https://github.com/satnaing/shadcn-admin)
(licencia en `LICENSE-shadcn-admin`). React 19 + Vite 8 + TypeScript + Tailwind 4 + shadcn/ui, TanStack Router /
Query / Table, zod 4, sonner, y cmdk. Gestor de paquetes: pnpm (`corepack pnpm ...` si no está en el PATH).

## Comandos

```powershell
corepack pnpm install
corepack pnpm dev        # http://localhost:5173, /api se reenvía a 127.0.0.1:8000 (TRACEWELL_API para otro destino)
corepack pnpm build      # tsc -b + vite build -> dist/ (lo sirve FastAPI en "/")
corepack pnpm test       # vitest + jsdom + MSW (sin navegador)
corepack pnpm lint       # eslint
corepack pnpm exec tsc -b
corepack pnpm knip       # archivos, exports y dependencias sin uso
corepack pnpm test:e2e   # Playwright: levanta su propio backend (ver e2e/README.md)
```

Desarrollo con el backend real: `.venv\Scripts\python.exe main.py --serve-only --port 8000` imprime
`http://127.0.0.1:8000/#token=...`. Abrí `http://localhost:5173/#token=<ese token>`: el token se lee del hash, se
guarda en `sessionStorage` y se limpia de la barra de direcciones.

## Estructura

```
src/
  main.tsx            lee el token ANTES de crear el router y monta <App/>
  app.tsx             providers: Query, tema, fuente, dirección, captura, router
  router.tsx          createAppRouter(queryClient, history?)
  routes/             TanStack Router (file-based). Cada ruta solo delega en features/
    _app/route.tsx    marco: barra lateral + Ctrl+K
    _app/index.tsx    Inicio (abrir archivo / demo / captura en vivo)
    _app/capturas/<seccion>/index.tsx     panorama alertas equipos trafico remoto cronologia sesiones indicadores reglas
    _app/soporte/{sistema,red}/$seccion/index.tsx
  features/<nombre>/  UNA carpeta por pantalla (index.tsx)
    sesiones/search.ts, alertas/search.ts   validateSearch (zod) de los filtros en la URL
  context/            capture-provider (captura cargada), theme, layout, direction, font, search (Ctrl+K)
  lib/api/            token.ts, client.ts (request + api.*), schemas.ts (zod), queries.ts, mutations.ts, errors.ts
  lib/query-client.ts QueryClient: errores de queries y mutations -> toast
  components/         ui/ (shadcn), layout/ (sidebar, header, main), page.tsx, severity-badge.tsx,
                      skeletons.tsx, query-boundary.tsx, empty-capture.tsx, command-menu.tsx, ...
  hooks/              use-shortcuts, use-dialog-state, use-mobile
  config/             support-sections.ts (secciones de Soporte de red)
  test/               setup.ts, render.tsx, handlers.ts (MSW), fixtures*.ts, server.ts
e2e/                  Playwright (aparte de vitest)
```

## Cómo se trabaja

**Captura cargada.** `useCapture()` (`context/capture-provider.tsx`) guarda el resultado de analizar un archivo, la
demo o la captura en vivo. Todas las queries de captura llevan `generation` en su clave y solo corren con una captura
cargada; al abrir o cerrar otra cambia y los datos viejos dejan de usarse (no hay `refreshKey`).
Envolvé el contenido de una pantalla en `<RequireCapture>` para mostrar "Sin captura cargada" si no hay ninguna.

**Agregar una pantalla.** Creá `features/<nombre>/index.tsx` y una ruta en `routes/_app/...` que la use (el árbol de rutas se
regenera solo con `pnpm dev` o `pnpm build`). Usá `<Page title=... description=... actions=...>` como marco y `QueryBoundary` para cargar datos.

**Agregar un endpoint.**

1. Esquema zod tolerante (`z.looseObject`, campos opcionales con `.nullish()`) en `lib/api/schemas.ts`.
2. Función en `api` de `lib/api/client.ts` (URL, método, esquema). Una respuesta que no calza lanza `ApiSchemaError`
   con un mensaje claro en vez de dejar la pantalla en blanco.
3. Hook en `queries.ts` (lectura; las de captura usan `useCaptureQuery`) o `mutations.ts` (acciones y pruebas).
4. Handler en `test/handlers.ts` + dato en `test/fixtures*.ts` y una línea en `lib/api/schemas.test.ts`.

**Errores.** `createQueryClient()` muestra un `toast.error()` por cada error de query o mutation (el `detail` del
backend va tal cual, también el 403 de carpetas permitidas). `meta: { silent: true }` lo evita si la pantalla
muestra su propio error.

**Filtros en la URL.** `validateSearch` con un esquema zod por ruta (`.catch()` descarta valores inválidos).

**Barra de progreso.** `NavigationProgress` se mueve al cambiar de pantalla y mientras corre cualquier mutation.

**Atajos.** Ctrl+K abre el menú de secciones; `useShortcuts({ '/': enfocarFiltro, Escape: cerrarPanel })` en cada
pantalla.

## Tema

`src/styles/theme.css` (oklch). Oscuro por defecto, claro opcional, primario cian. Severidades:
`--sev-low` (sky), `--sev-medium` (amber), `--sev-high` (orange), `--sev-critical` (rose), utilidades `text-sev-*`,
`bg-sev-*/10` y el componente `<SeverityBadge severity='high' />`. Contraste AA (>= 4.5:1) verificado por cálculo
(luminancia relativa WCAG sobre `oklch`): texto y fondo 17:1, texto atenuado 5.3 a 7.3, primario 6.0 (claro) y
10.8 (oscuro), severidades 4.9 a 6.4 sobre su fondo tintado al 10% en ambos modos. No hay fuentes externas (la CSP
del backend solo permite `'self'`): se usa la pila del sistema.

## Pruebas

`src/test/render.tsx` ofrece `renderRoute(path, { capture })` (la app completa con router en memoria),
`renderWithProviders(ui, { capture })` y `renderHookWithProviders(hook, { capture })`. MSW (`test/server.ts`) responde
todos los endpoints con datos de `samples/demo.pcap`; un pedido sin handler falla la prueba. Con `capture: true` el
backend simulado ya tiene una captura cargada. Para un caso puntual: `server.use(http.get('/api/...', ...))`.
