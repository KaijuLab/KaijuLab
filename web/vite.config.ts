import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// During dev, proxy /api and /api/events (WS) to the running `kaijulab serve`
// daemon so we can hot-reload the UI without rebuilding the Rust binary.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2020',
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7878',
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
