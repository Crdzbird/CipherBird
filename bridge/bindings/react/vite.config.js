import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// During `npm run dev`, proxy API calls to the Node+koffi server (server.mjs).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': 'http://localhost:8787' },
  },
});
