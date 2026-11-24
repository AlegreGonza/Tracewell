import { existsSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { defineConfig, devices } from '@playwright/test'

// E2E contra el backend real, que sirve `dist/` (hay que compilar antes: `pnpm build`).
// Levanta su propio servidor con token fijo y una carpeta de reglas temporal, así que no toca
// las reglas del usuario. Chromium no viene instalado: `pnpm test:e2e:install`.
// Usa el .venv del repo si existe (en CI el Python ya trae las dependencias).
const venvPython = ['.venv/Scripts/python.exe', '.venv/bin/python'].find((p) =>
  existsSync(join(process.cwd(), '..', p))
)
const PORT = 8765
const TOKEN = 'e2e-token-0123456789abcdef'
process.env.E2E_TOKEN = TOKEN

export default defineConfig({
  testDir: './e2e',
  // Un solo servidor y una sola captura en memoria: los recorridos van en serie.
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `${venvPython ? `"${join(process.cwd(), '..', venvPython)}"` : 'python'} main.py --serve-only --port ${PORT}`,
    cwd: '..',
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      TRACEWELL_API_TOKEN: TOKEN,
      TRACEWELL_USER_RULES_DIR: mkdtempSync(join(tmpdir(), 'tracewell-e2e-')),
    },
  },
})
