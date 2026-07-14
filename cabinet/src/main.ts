import { App } from "./ui/app.ts";

const root = document.getElementById("app");
if (!root) {
  throw new Error("missing #app mount point");
}

const app = new App(root, window.sessionStorage, window.location.hostname, navigator.language);
void app.start();
