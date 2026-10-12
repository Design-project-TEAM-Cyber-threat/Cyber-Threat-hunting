import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard calls the Django API at the same origin ("/api/...") and the Vite dev server
// forwards those requests to Django. 127.0.0.1 is used on purpose (not "localhost") so Windows
// does not try IPv6 first. Change BACKEND if Django runs somewhere else.
const BACKEND = process.env.VITE_BACKEND_URL || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: BACKEND,
        changeOrigin: true,
        configure: (proxy) => {
          // If Django is not running, answer with a clear 502 the dashboard understands.
          proxy.on("error", (_err, _req, res) => {
            if (res && !res.headersSent && typeof res.writeHead === "function") {
              res.writeHead(502, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "backend_unavailable" }));
            }
          });
        },
      },
    },
  },
});
