import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  server: {
    port: 5173,
    host: '0.0.0.0',
    proxy: {
      // 控制台 API
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
      // WebSocket 实时推送
      '/ws': { target: 'ws://localhost:8080', ws: true, changeOrigin: true },
      // 经网关访问靶场，用于演练台发起攻击
      '/range-gw': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/range-gw/, '')
      },
      // 直连靶场，用于对比演示
      '/range-direct': {
        target: 'http://localhost:8090',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/range-direct/, '')
      }
    }
  },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 1600 }
})
