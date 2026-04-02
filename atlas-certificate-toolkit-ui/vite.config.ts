import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  preview: {
    host: "0.0.0.0",
    port: 4173
  },
  server: {
    proxy: {
      "/toolkit": "http://localhost:3000",
      "/health": "http://localhost:3000",
      "/debug": "http://localhost:3000"
    }
  }
});
