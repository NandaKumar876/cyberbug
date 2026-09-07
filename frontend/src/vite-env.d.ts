/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Render backend base URL, e.g. https://cyberbug.onrender.com
   *  Leave empty (or unset) in development — Vite's dev proxy handles /api requests. */
  readonly VITE_API_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
