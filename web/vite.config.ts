import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// make dev：前端热更新，/api 转给本机跑着的 dialhome 控制面（DIALHOME_CONTROL_LISTEN=127.0.0.1:7900）。
// 注意 passkey 要 https + 域名，本地 http://localhost 上只看得了界面，登录走不通 —— 真验在 VPS 上。
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": new URL("./src", import.meta.url).pathname } },
  server: { proxy: { "/api": "http://127.0.0.1:7900" } },
});
