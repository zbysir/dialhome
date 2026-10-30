import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";

// 明暗跟系统走（gerdr 那边是设置里选，这里只有一个页面，不值得再加一个开关）
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const apply = () => document.documentElement.classList.toggle("dark", dark.matches);
apply();
dark.addEventListener("change", apply);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
