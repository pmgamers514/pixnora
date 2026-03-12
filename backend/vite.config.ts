import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  return {
    plugins: [
      react(),
      tailwindcss()
    ],

    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./")
      }
    },

    define: {
      __APP_ENV__: JSON.stringify(mode)
    },

    server: {
      host: "0.0.0.0",
      port: 5173,
      strictPort: true,
      open: false,
      hmr: process.env.DISABLE_HMR !== "true"
    },

    preview: {
      host: "0.0.0.0",
      port: 4173
    },

    build: {
      outDir: "dist",
      sourcemap: mode !== "production",
      minify: "esbuild",

      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ["react", "react-dom"]
          }
        }
      }
    },

    optimizeDeps: {
      include: ["react", "react-dom"]
    }
  };
});
