// Minimal vanilla-DOM helpers — the project has no framework dependency
// (D12/proposal: "БЕЗ фреймворков и БЕЗ runtime-зависимостей"), so these are
// the few conveniences that make hand-written DOM construction bearable.

export type Children = (Node | string | undefined | false)[];

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | undefined> = {},
  children: Children = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined) continue;
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === undefined || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: Element): void {
  node.replaceChildren();
}

/** Read a `<input type=file>`'s single selected file as text (UTF-8). */
export function readFileAsText(input: HTMLInputElement): Promise<string> {
  const file = input.files?.[0];
  if (!file) return Promise.reject(new Error("no file selected"));
  return file.text();
}

/** Read a `<input type=file>`'s single selected file as raw bytes, Base64-encoded. */
export async function readFileAsBase64(input: HTMLInputElement): Promise<string> {
  const file = input.files?.[0];
  if (!file) throw new Error("no file selected");
  const buffer = await file.arrayBuffer();
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Trigger a browser download of `content` as `filename`. */
export function downloadText(filename: string, content: string, mime = "text/plain"): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
