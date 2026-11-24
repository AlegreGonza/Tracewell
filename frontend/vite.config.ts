/// <reference types="vitest/config" />
import path from 'path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'

// FastAPI sirve `dist/` en "/" (backend/api/app.py): el base absoluto "/" alcanza.
// En desarrollo, `/api` se reenvía al backend (python main.py --serve-only --port 8000).
const API_TARGET = process.env.TRACEWELL_API ?? 'http://127.0.0.1:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: { '/api': API_TARGET },
  },
  build: {
    outDir: 'dist',
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: 'recharts',
              test: /node_modules[\\/](\.pnpm[\\/])?(recharts|d3-[^\\/]+|victory-vendor|decimal\.js-light|internmap)/,
            },
          ],
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    unstubEnvs: true,
    coverage: {
      exclude: [
        'src/components/ui/**',
        'src/assets/**',
        'src/tanstack-table.d.ts',
        'src/routeTree.gen.ts',
        'src/test/**',
      ],
    },
  },
})
