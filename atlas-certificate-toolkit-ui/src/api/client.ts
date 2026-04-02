import { extractErrorMessage } from "../utils/errorResponse";

function apiBaseUrl() {
  return import.meta.env.VITE_API_BASE ?? "http://localhost:3000";
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${apiBaseUrl()}${path}`, init);

  if (!res.ok) {
    const message = await extractErrorMessage(
      res.headers.get("content-type"),
      () => res.json(),
      () => res.text()
    );
    throw new Error(message || `HTTP ${res.status}`);
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await res.json()) as T;
  }

  return (await res.text()) as unknown as T;
}

export async function apiDownload(path: string, init?: RequestInit): Promise<Blob> {
  const res = await fetch(`${apiBaseUrl()}${path}`, init);

  if (!res.ok) {
    const message = await extractErrorMessage(
      res.headers.get("content-type"),
      () => res.json(),
      () => res.text()
    );
    throw new Error(message || `HTTP ${res.status}`);
  }

  return res.blob();
}
