import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En desarrollo (npm run dev) el front corre en :5173 y reenvía /api a la API
// en :8000, así el código usa rutas relativas igual que en producción, donde
// FastAPI sirve los estáticos compilados desde el mismo origen (sin CORS).
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
  build: { outDir: "dist", emptyOutDir: true },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.js",
  },
});
