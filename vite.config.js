import { defineConfig } from 'vite';

// https://vitejs.dev/config/
export default defineConfig({
  // Use relative base so assets load correctly on GitHub Pages (e.g., https://<username>.github.io/<repo>/)
  // as well as custom domains or local previews
  base: './',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false
  }
});
