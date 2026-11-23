import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/enterprise': 'http://localhost:8080',
      '/auth': 'http://localhost:8080',
      '/webhook': 'http://localhost:8080',
      '/assessments': 'http://localhost:8080',
    }
  }
})