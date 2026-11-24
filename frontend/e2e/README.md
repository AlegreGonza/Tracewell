# e2e (Playwright)

Flujos de extremo a extremo contra el backend real, que sirve `frontend/dist`.

1. `corepack pnpm build` (el backend sirve `frontend/dist`).
2. `corepack pnpm test:e2e:install` (una vez: descarga Chromium).
3. `corepack pnpm test:e2e`. Levanta solo su backend en el puerto 8765 con token fijo y una carpeta de
   reglas temporal; no toca tus reglas ni tu captura.

Los archivos `*.spec.ts` van acá; `vitest` solo corre `src/**/*.test.{ts,tsx}`.
