import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    // `@/x` means `src/x` (must match "paths" in tsconfig.json / tsconfig.app.json)
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  server: {
    proxy: {
      // Dev only: forward API calls to FastAPI so the browser sees ONE origin (localhost:5173),
      // exactly like production where FastAPI serves both the UI and /api.
      // No CORS needed, and the httpOnly session cookie just works.
      '/api': process.env.VITE_API_PROXY_TARGET ?? 'http://localhost:8000',
    },
  },
})
